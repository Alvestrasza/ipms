# File Name: gpo_views.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Explicit tenant-admin unlinked pilot requests; settings never trigger import.
from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from .domains import DomainSettingsView
from .gpo_jobs import executor_options, expire_jobs, job_projection, queue_job
from .models import DomainSecuritySettings, GpoImportJob
from .views import query


class DomainGpoImportsView(DomainSettingsView):
    @transaction.atomic
    def get(self, request, domain_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        self.check_permissions(request)
        config = get_object_or_404(DomainSecuritySettings, pk=domain_id, tenant=request.tenant)
        expire_jobs(request.tenant)
        jobs = GpoImportJob.objects.filter(tenant=request.tenant, domain=config).select_related('system')[:50]
        return Response({'results': [job_projection(job) for job in jobs], 'executors': executor_options(request.tenant, config)})

    @transaction.atomic
    def post(self, request, domain_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        self.check_permissions(request)
        if not has_tenant_permission(request.user, request.tenant, Permission.SECURITY_GPO_IMPORTS_RUN):
            raise PermissionDenied()
        config = get_object_or_404(DomainSecuritySettings.objects.select_for_update(), pk=domain_id, tenant=request.tenant)
        job = queue_job(request.tenant, request.user, config, request.data)
        return Response(job_projection(job), status=202)
