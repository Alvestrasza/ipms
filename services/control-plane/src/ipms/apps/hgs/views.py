# File Name: views.py
# Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-19
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Session-only HGS planning and reviewed execution for a dedicated tenant.
from django.core.exceptions import ValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ParseError, PermissionDenied
from rest_framework.response import Response

from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.security.administration import SmallJSONParser
from ipms.apps.security.views import SecurityReadView, query
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from . import contract, services
from .models import HgsDeployment


class HgsParser(SmallJSONParser):
    maximum_bytes = 8192


class HgsView(SecurityReadView):
    authentication_classes = (SessionAuthentication,)
    parser_classes = (HgsParser,)
    http_method_names = ("get", "post", "head", "options")

    def tenant(self, request, *, write=False):
        query(request, set())
        tenant = Tenant.objects.select_for_update().get(pk=request.tenant.id)
        request.tenant = tenant
        self.check_permissions(request)
        if write and not has_tenant_permission(request.user, tenant, Permission.HGS_MANAGE):
            raise PermissionDenied()
        return tenant


class HgsOverviewView(HgsView):
    @transaction.atomic
    def get(self, request):
        tenant = self.tenant(request)
        overview = {"tenant_purpose": tenant.purpose, "can_manage": has_tenant_permission(request.user, tenant, Permission.HGS_MANAGE),
                    "profiles": contract.PROFILES, "systems": [], "deployments": [], "single_appliance_supported": True}
        if tenant.purpose != "hgs":
            return Response(overview)
        enrollments = {e.device_uri: e for e in AgentEnrollment.objects.filter(tenant=tenant, platform="windows")}
        for system in WindowsServer.objects.filter(tenant=tenant, inventory_source="agent").order_by("hostname")[:250]:
            reason = services.eligible(system, enrollments.get(system.source_id))
            overview["systems"].append({"id": str(system.id), "hostname": system.hostname, "agent_version": system.agent_version,
                                       "eligible": not reason, "reason": reason})
        overview["deployments"] = [services.projection(p) for p in HgsDeployment.objects.filter(tenant=tenant).prefetch_related("nodes", "jobs")[:50]]
        return Response(overview)


class HgsDeploymentListView(HgsView):
    @transaction.atomic
    def post(self, request):
        tenant = self.tenant(request, write=True)
        try:
            plan = services.create_plan(tenant, request.user, request.data)
        except ValidationError as exc:
            raise ParseError("Invalid HGS plan.") from exc
        return Response(services.projection(plan), status=201)


class HgsDeploymentView(HgsView):
    @transaction.atomic
    def get(self, request, pk):
        tenant = self.tenant(request)
        if tenant.purpose != "hgs":
            raise PermissionDenied()
        plan = get_object_or_404(HgsDeployment, pk=pk, tenant=tenant)
        return Response(services.projection(plan))


class HgsActionView(HgsView):
    operation = ""

    @transaction.atomic
    def post(self, request, pk):
        tenant = self.tenant(request, write=True)
        plan = get_object_or_404(HgsDeployment.objects.select_for_update(), pk=pk, tenant=tenant)
        plan.tenant = tenant
        data = request.data
        if self.operation not in ("execute", "resolve") and data != {}:
            raise ParseError("No action parameters are accepted.")
        try:
            if self.operation == "inspect":
                services.request_inspection(plan, actor=request.user)
            elif self.operation == "reconcile":
                services.request_inspection(plan, actor=request.user, reconciliation=True)
            elif self.operation == "execute":
                services.authorize(plan, request.user, data)
            elif self.operation == "cancel":
                services.cancel(plan)
            elif self.operation == "resolve":
                services.resolve(plan, request.user, data)
            else:
                raise ParseError("Unsupported HGS action.")
        except ValidationError as exc:
            raise ParseError("Invalid HGS action.") from exc
        return Response(services.projection(plan), status=202)
