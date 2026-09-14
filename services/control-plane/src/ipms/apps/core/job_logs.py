# File Name: job_logs.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Read-only, tenant-scoped job history with bounded sorting, filtering and safe CSV export.
import csv
import io
import re
import unicodedata
import uuid
from datetime import datetime, time, timedelta, timezone as datetime_timezone

from django.db.models import DateTimeField, F, Q, TextField, Value
from django.db.models.fields.json import KeyTextTransform
from django.db.models.functions import Cast, Coalesce
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_date, parse_datetime
from django.utils.timezone import is_naive
from rest_framework.exceptions import ParseError
from rest_framework.response import Response

from ipms.apps.agent_pki.models import AgentLifecycleJob, WindowsAgentDeployment
from ipms.apps.discovery.models import HyperVManagementJob, HyperVVirtualMachineActionJob
from ipms.apps.security.domains import CanManageDomains
from ipms.apps.security.gpo_jobs import job_projection
from ipms.apps.security.models import BaselineScanJob, GpoImportJob
from ipms.apps.security.views import SecurityReadView, query
from ipms.apps.tenancy.rbac import Permission, effective_tenant_permissions
from .exceptions import PublicApiError


FIELDS = (
    "id", "kind", "action", "status", "system", "target", "enrollment_id", "baseline_id",
    "domain", "requested_at", "started_at", "completed_at", "result_code", "requested_by",
)
KINDS = {
    "agent_lifecycle": Permission.AGENTS_MANAGE,
    "agent_deployment": Permission.AGENTS_MANAGE,
    "baseline_scan": Permission.INVENTORY_VIEW,
    "gpo_import": Permission.SECURITY_DOMAINS_MANAGE,
    "hyperv_power": Permission.VIRTUAL_MACHINES_OPERATE,
    "hyperv_management": Permission.INVENTORY_VIEW,
}
STATUSES = frozenset({
    "queued", "delivered", "running", "succeeded", "failed", "cancelled", "completed", "expired",
    "awaiting_approval", "staged", "blocked", "reconciliation_required", "requires_reconciliation",
})
SORTS = {"requested_at", "completed_at", "system", "kind", "status"}
QUERY_FIELDS = {"q", "kind", "status", "from", "to", "baseline", "domain", "agent", "sort", "direction", "page", "page_size"}
EXPORT_LIMIT = 10000


def _text(expression):
    return Coalesce(Cast(expression, TextField()), Value("", output_field=TextField()))


def _literal(value):
    return Value(value, output_field=TextField())


def _source(model, tenant, kind, *, relations=(), **fields):
    """Only named metadata columns leave the database; payload/secret columns are never selected."""
    values = {name: _literal("") for name in FIELDS}
    values.update({
        "id": _text(F("id")), "kind": _literal(kind), "status": _text(F("status")),
        "enrollment_id": _text(F("enrollment_id")), "system": _text(F("enrollment__display_name")),
        "requested_at": F("created_at"), "started_at": F("started_at"), "completed_at": F("completed_at"),
        "requested_by": _text(F("requested_by")),
    })
    values.update(fields)
    scope = {"tenant": tenant, "enrollment__tenant": tenant}
    scope.update({f"{relation}__tenant": tenant for relation in relations})
    return model.objects.filter(**scope).order_by().values(**{f"log_{name}": values[name] for name in FIELDS})


def _sources(tenant):
    missing_time = Value(None, output_field=DateTimeField())
    return {
        "agent_lifecycle": _source(AgentLifecycleJob, tenant, "agent_lifecycle",
            action=_text(F("action")), target=_text(F("target_version")), result_code=_text(F("result_code"))),
        "agent_deployment": _source(WindowsAgentDeployment, tenant, "agent_deployment",
            action=_literal("install"), system=_text(F("display_name")), target=_text(F("target_address")),
            result_code=_text(F("error_code"))),
        "baseline_scan": _source(BaselineScanJob, tenant, "baseline_scan", relations=("system",),
            action=_literal("scan"), system=_text(F("system__hostname")), target=_text(F("baseline_id")),
            baseline_id=_text(F("baseline_id")), domain=_text(F("system__domain_name")),
            requested_at=F("requested_at"), started_at=missing_time, result_code=_text(F("error_code")),
            requested_by=_text(F("requested_by__username"))),
        "gpo_import": _source(GpoImportJob, tenant, "gpo_import", relations=("system", "domain"),
            action=_literal("pilot_import"), system=_text(F("system__hostname")),
            target=_text(F("pilot_display_name")), baseline_id=_text(KeyTextTransform("baseline_id", "assignment")),
            domain=_text(F("domain__domain_name")), requested_at=F("requested_at"), started_at=F("claimed_at"),
            result_code=_text(F("error_code")), requested_by=_text(F("requested_by__username"))),
        "hyperv_power": _source(HyperVVirtualMachineActionJob, tenant, "hyperv_power",
            action=_text(F("action")), target=_text(F("vm_name")), result_code=_text(F("result_code"))),
        "hyperv_management": _source(HyperVManagementJob, tenant, "hyperv_management",
            action=_text(F("operation")), target=_text(F("vm_name")), result_code=_text(F("result_code"))),
    }


def _date(raw, *, end=False):
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
            parsed = datetime.combine(parse_date(raw), time.min, tzinfo=datetime_timezone.utc)
            return parsed + timedelta(days=1) if end else parsed
        parsed = parse_datetime(raw)
        if parsed is None or is_naive(parsed):
            raise ValueError
        return parsed
    except (ValueError, TypeError, OverflowError) as exc:
        raise ParseError("Use a valid UTC date or a timestamp including its timezone.") from exc


def _options(request):
    query(request, QUERY_FIELDS)
    params = request.query_params
    result = {key: params.get(key, "").strip() for key in QUERY_FIELDS}
    for key, limit in (("q", 200), ("domain", 253), ("baseline", 96), ("from", 64), ("to", 64)):
        if len(result[key]) > limit or any(ord(char) < 32 for char in result[key]):
            raise ParseError("The log filter is too long or contains control characters.")
    if result["kind"] and result["kind"] not in KINDS:
        raise ParseError("Unsupported job kind.")
    if result["status"] and result["status"] not in STATUSES:
        raise ParseError("Unsupported job status.")
    result["sort"] = result["sort"] or "requested_at"
    result["direction"] = result["direction"] or "desc"
    if result["sort"] not in SORTS or result["direction"] not in {"asc", "desc"}:
        raise ParseError("Unsupported log sort.")
    page = result["page"] or "1"
    if not page.isascii() or not page.isdecimal() or len(page) > 7 or int(page) < 1:
        raise ParseError("A positive page number is required.")
    result["page"] = int(page)
    if result["page_size"] not in {"", "25", "50", "100"}:
        raise ParseError("Unsupported log page size.")
    result["page_size"] = int(result["page_size"] or "25")
    if result["agent"]:
        try:
            result["agent"] = str(uuid.UUID(result["agent"]))
        except ValueError as exc:
            raise ParseError("Invalid Agent identity.") from exc
    result["until_exclusive"] = bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", result["to"]))
    result["since"] = _date(result["from"]) if result["from"] else None
    result["until"] = _date(result["to"], end=True) if result["to"] else None
    if result["since"] and result["until"] and (
        result["since"] > result["until"] or (result["until_exclusive"] and result["since"] == result["until"])
    ):
        raise ParseError("The log date range is reversed.")
    return result


def _filtered(source, options):
    if options["agent"]:
        source = source.filter(enrollment_id=options["agent"])
    for key, column, lookup in (("status", "status", "exact"), ("baseline", "baseline_id", "exact"), ("domain", "domain", "iexact")):
        if options[key]:
            source = source.filter(**{f"log_{column}__{lookup}": options[key]})
    if options["since"]:
        source = source.filter(log_requested_at__gte=options["since"])
    if options["until"]:
        source = source.filter(**{f"log_requested_at__{'lt' if options['until_exclusive'] else 'lte'}": options["until"]})
    if options["q"]:
        search = Q()
        for column in ("system", "target", "domain", "baseline_id", "result_code", "requested_by", "action", "id"):
            search |= Q(**{f"log_{column}__icontains": options["q"]})
        source = source.filter(search)
    return source


def _rows(request, scope, options):
    permissions = effective_tenant_permissions(request.user, request.tenant)
    kinds = [kind for kind, permission in KINDS.items() if permission in permissions
             and (scope == "agents" or kind in {"baseline_scan", "gpo_import"})]
    sources = _sources(request.tenant)
    selected = [_filtered(sources[kind], options) for kind in kinds if not options["kind"] or kind == options["kind"]]
    if not selected:
        return sources["baseline_scan"].none(), kinds
    rows = selected[0].union(*selected[1:], all=True) if len(selected) > 1 else selected[0]
    column = F(f"log_{options['sort']}")
    ordering = column.asc(nulls_last=True) if options["direction"] == "asc" else column.desc(nulls_last=True)
    return rows.order_by(ordering, "log_kind", "log_id"), kinds


def _public(row):
    result = {key: row[f"log_{key}"] for key in FIELDS}
    for key in ("id", "enrollment_id"):
        result[key] = str(uuid.UUID(result[key]))
    return result


def _csv_safe(value):
    text = "" if value is None else (value.isoformat() if isinstance(value, datetime) else str(value))
    # Excel may ignore leading whitespace/control characters before interpreting formulas.
    for character in text:
        if character.isspace() or unicodedata.category(character) in ("Cc", "Cf"):
            continue
        if character in "=+-@":
            return f"'{text}"
        break
    return text


class JobLogView(SecurityReadView):
    scope = "agents"
    export = False

    def get(self, request):
        options = _options(request)
        rows, kinds = _rows(request, self.scope, options)
        if self.export:
            # The extra row makes an oversized export explicit, never silently partial.
            entries = list(rows[:EXPORT_LIMIT + 1])
            if len(entries) > EXPORT_LIMIT:
                raise PublicApiError("log_export_limit_exceeded")
            output = io.StringIO(newline="")
            output.write("\ufeff")
            writer = csv.writer(output)
            writer.writerow(FIELDS)
            for row in entries:
                public = _public(row)
                writer.writerow(_csv_safe(public[key]) for key in FIELDS)
            response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
            response["Content-Disposition"] = f'attachment; filename="ipms-{self.scope}-logs.csv"'
            return response
        offset = (options["page"] - 1) * options["page_size"]
        return Response({"count": rows.count(), "page": options["page"], "page_size": options["page_size"],
                         "available_kinds": kinds,
                         "results": [_public(row) for row in rows[offset:offset + options["page_size"]]]})


class GpoImportLogDetailView(SecurityReadView):
    permission_classes = (*SecurityReadView.permission_classes, CanManageDomains)

    def get(self, request, pk):
        query(request, set())
        job = get_object_or_404(GpoImportJob.objects.select_related("system", "domain"),
            pk=pk, tenant=request.tenant, enrollment__tenant=request.tenant,
            system__tenant=request.tenant, domain__tenant=request.tenant)
        return Response({**job_projection(job), "domain_id": str(job.domain_id), "domain": job.domain.domain_name})
