# File Name: administration.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Strict tenant-admin visibility settings; never delete baseline evidence.
import json

from django.db import transaction
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import NotFound, ParseError
from rest_framework.parsers import BaseParser

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.permissions import HasTenantPermission
from ipms.apps.tenancy.rbac import Permission
from .catalog import BY_ID, CATALOG_REVISION
from .models import BaselinePreference
from .services import BaselineOverview
from .views import SecurityReadView, query
from rest_framework.response import Response


class SmallJSONParser(BaseParser):
    media_type = "application/json"
    maximum_bytes = 4096

    def parse(self, stream, media_type=None, parser_context=None):
        raw = stream.read(self.maximum_bytes + 1)
        if len(raw) > self.maximum_bytes:
            raise PublicApiError("security_payload_too_large", status_code=413)

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        try:
            return json.loads(raw, object_pairs_hook=unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise ParseError("Invalid Security JSON document.") from exc


class CanManageBaselines(HasTenantPermission):
    required_permission = Permission.SECURITY_BASELINES_MANAGE


class BaselineSettingsView(SecurityReadView):
    authentication_classes = (SessionAuthentication,)
    permission_classes = (*SecurityReadView.permission_classes, CanManageBaselines)
    parser_classes = (SmallJSONParser,)

    def get(self, request):
        query(request, set())
        overview = BaselineOverview(request.tenant)
        rows = overview.catalog(include_hidden=True)["results"]
        for row in rows:
            preference = overview.preferences.get(row["id"])
            row["hidden"] = bool(preference and preference.hidden)
            row["updated_at"] = preference.updated_at.isoformat() if preference else None
        return Response({"catalog_revision": CATALOG_REVISION, "results": rows})


class BaselineSettingView(BaselineSettingsView):
    http_method_names = ("patch", "options")

    @transaction.atomic
    def patch(self, request, baseline_id):
        query(request, set())
        tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        request.tenant = tenant
        self.check_permissions(request)
        if tenant.status != Tenant.Status.ACTIVE or baseline_id not in BY_ID:
            raise NotFound("Baseline not found.")
        data = request.data
        if not isinstance(data, dict) or set(data) != {"hidden"} or type(data["hidden"]) is not bool:
            raise ParseError("Supply exactly one boolean hidden setting.")
        preference, created = BaselinePreference.objects.get_or_create(
            tenant=tenant, baseline_id=baseline_id, defaults={"hidden": data["hidden"]},
        )
        changed = preference.hidden != data["hidden"]
        if changed:
            preference.hidden = data["hidden"]
            preference.save(update_fields=("hidden", "updated_at"))
        if changed or (created and preference.hidden):
            AuditEvent.objects.create(
                tenant=tenant, actor=str(request.user.pk), action="security.baseline_visibility_changed",
                object_type="security_baseline", object_id=baseline_id, outcome=AuditEvent.Outcome.SUCCEEDED,
                details={"hidden": preference.hidden},
            )
        return Response({"id": baseline_id, "hidden": preference.hidden, "updated_at": preference.updated_at.isoformat()})
