# File Name: views.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Read-only tenant-scoped baseline catalog and paginated system assessment API.
from rest_framework.exceptions import NotFound, ParseError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.tenancy.permissions import HasSelectedTenantAccess, HasTenantPermission
from ipms.apps.tenancy.rbac import Permission
from .catalog import BY_ID
from .services import BaselineOverview


class CanReadSecurity(HasTenantPermission):
    required_permission = Permission.INVENTORY_VIEW


def query(request, allowed):
    if set(request.query_params) - allowed or any(len(values) != 1 for _, values in request.query_params.lists()):
        raise ParseError("Unsupported or repeated query parameter.")


class SecurityReadView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanReadSecurity)
    http_method_names = ("get", "head", "options")

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["Cache-Control"] = "no-store"
        return response


class BaselineListView(SecurityReadView):
    def get(self, request):
        query(request, {"target"})
        target = request.query_params.get("target", "all")
        if target not in ("all", "server", "client"):
            raise ParseError("Unsupported baseline target.")
        return Response(BaselineOverview(request.tenant).catalog(target))


class BaselineSystemListView(SecurityReadView):
    def get(self, request, baseline_id):
        query(request, {"page"})
        baseline = BY_ID.get(baseline_id)
        if baseline is None:
            raise NotFound("Baseline not found.")
        raw_page = request.query_params.get("page", "1")
        if not raw_page.isascii() or not raw_page.isdecimal() or len(raw_page) > 7 or int(raw_page) < 1:
            raise ParseError("A positive page number is required.")
        page = int(raw_page)
        overview = BaselineOverview(request.tenant)
        rows = overview.systems_for(baseline)
        return Response({
            "baseline": overview.baseline(baseline, rows), "count": len(rows),
            "page": page, "page_size": 25, "results": rows[(page - 1) * 25:page * 25],
        })
