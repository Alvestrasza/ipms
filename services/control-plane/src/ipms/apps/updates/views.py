# File Name: views.py
# Version: v0.2.0
# Created: 2026-09-13
# Last Modified: 2026-09-13
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Authorized source configuration, metadata-only ingress and comparison APIs.
import ipaddress
import re

from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import serializers
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.permissions import HasSelectedTenantAccess, HasTenantPermission
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from .authentication import WsusSourceAuthentication, issue_token
from .contract import BoundedJSONParser, SnapshotSerializer, StrictSerializer
from .models import UpdateSource
from .services import Comparison, audit, ingest, snapshot_projection, source_projection


class CanReadUpdates(HasTenantPermission):
    required_permission = Permission.INVENTORY_VIEW


WSUS_FIELDS = frozenset(("wsus_host", "wsus_port", "wsus_use_ssl"))


class PortField(serializers.IntegerField):
    def to_internal_value(self, data):
        if type(data) is not int:
            raise serializers.ValidationError("A numeric port is required.")
        return super().to_internal_value(data)


class SslField(serializers.BooleanField):
    def to_internal_value(self, data):
        if type(data) is not bool:
            raise serializers.ValidationError("A boolean HTTPS setting is required.")
        return super().to_internal_value(data)


class WsusSettingsSerializer(StrictSerializer):
    wsus_host = serializers.CharField(max_length=253, required=False)
    wsus_port = PortField(min_value=1, max_value=65535, required=False)
    wsus_use_ssl = SslField(required=False)

    def validate_wsus_host(self, value):
        value = value.lower().rstrip(".")
        if "%" not in value:
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                pass
        if not value or re.fullmatch(r"[0-9.]+", value) or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in value.split(".")
        ):
            raise serializers.ValidationError("Use a DNS name or IP address without a URL, port or credentials.")
        return value

    def validate(self, data):
        supplied = WSUS_FIELDS.intersection(data)
        if supplied and supplied != WSUS_FIELDS:
            raise serializers.ValidationError("Supply the complete WSUS endpoint.")
        return data


class SourceCreateSerializer(WsusSettingsSerializer):
    name = serializers.CharField(max_length=128)
    scope = serializers.CharField(max_length=255)


class SourceChangeSerializer(WsusSettingsSerializer):
    enabled = serializers.BooleanField(required=False)

    def validate(self, data):
        if not data:
            raise serializers.ValidationError("Supply a configuration change.")
        return super().validate(data)


def manage(request):
    if not has_tenant_permission(request.user, request.tenant, Permission.CONNECTORS_MANAGE):
        raise PublicApiError("forbidden", status_code=403)


def selected_source(request, pk, *, lock=False):
    queryset = UpdateSource.objects.filter(tenant=request.tenant)
    if lock:
        Tenant.objects.select_for_update().get(id=request.tenant.id)
        # Revalidate membership/status inside the transaction too.
        manage(request)
        if Tenant.objects.get(id=request.tenant.id).status != "active":
            raise PublicApiError("not_found", status_code=404)
        queryset = queryset.select_for_update()
    return get_object_or_404(queryset, id=pk)


def page(items, request):
    raw = request.query_params.get("page", "1")
    if not raw.isascii() or not raw.isdigit() or len(raw) > 6 or int(raw) < 1:
        raise PublicApiError("invalid_page")
    number = int(raw)
    return {"count": len(items), "page": number, "page_size": 50,
            "results": items[(number - 1) * 50:number * 50]}


class TenantUpdateView(APIView):
    authentication_classes = (SessionAuthentication,)
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanReadUpdates)
    parser_classes = (BoundedJSONParser,)

    def finalize_response(self, *args, **kwargs):
        response = super().finalize_response(*args, **kwargs)
        response["Cache-Control"] = "no-store"
        return response


class SourceListView(TenantUpdateView):
    def get(self, request):
        return Response([source_projection(s) for s in UpdateSource.objects.filter(
            tenant=request.tenant).select_related("current_snapshot")])

    @transaction.atomic
    def post(self, request):
        manage(request)
        tenant = Tenant.objects.select_for_update().get(id=request.tenant.id)
        manage(request)
        if tenant.status != "active":
            raise PublicApiError("not_found", status_code=404)
        serializer = SourceCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if UpdateSource.objects.filter(tenant=tenant).count() >= 20:
            raise PublicApiError("wsus_source_limit")
        source = UpdateSource.objects.create(tenant=tenant, **serializer.validated_data)
        token = issue_token(source)
        audit(source, str(request.user.pk), "updates.source_created")
        return Response({**source_projection(source), "token": token}, status=201)


class SourceDetailView(TenantUpdateView):
    @transaction.atomic
    def patch(self, request, pk):
        source = selected_source(request, pk, lock=True)
        serializer = SourceChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        changes = serializer.validated_data
        endpoint_changed = any(name in changes and getattr(source, name) != changes[name] for name in WSUS_FIELDS)
        for name, value in changes.items():
            setattr(source, name, value)
        fields = set(changes)
        if endpoint_changed:
            # Do not attribute the old server's catalog to newly configured settings.
            source.current_snapshot = None
            source.wsus_changed_at = timezone.now()
            fields.update(("current_snapshot", "wsus_changed_at"))
        source.save(update_fields=fields)
        audit(source, str(request.user.pk), "updates.source_changed", enabled=source.enabled,
              wsus_endpoint_changed=endpoint_changed)
        return Response(source_projection(source))


class SourceRotateView(TenantUpdateView):
    @transaction.atomic
    def post(self, request, pk):
        source = selected_source(request, pk, lock=True)
        token = issue_token(source)
        audit(source, str(request.user.pk), "updates.source_token_rotated")
        return Response({"token": token})


class SnapshotReceiveView(APIView):
    authentication_classes = (WsusSourceAuthentication,)
    permission_classes = (IsAuthenticated,)
    parser_classes = (BoundedJSONParser,)

    def post(self, request, pk):
        serializer = SnapshotSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        snapshot, created = ingest(request.auth, serializer.validated_data)
        response = Response({"snapshot": snapshot_projection(snapshot), "duplicate": not created},
                            status=201 if created else 200)
        response["Cache-Control"] = "no-store"
        return response


class ComparisonView(TenantUpdateView):
    @transaction.atomic
    def get(self, request, pk):
        source = get_object_or_404(UpdateSource.objects.select_for_update(), tenant=request.tenant, id=pk)
        comparison = Comparison(source)
        result = page(comparison.servers, request)
        result["results"] = [comparison.row(s) for s in result["results"]]
        return Response({**result, "source": source_projection(source),
                         "snapshot": snapshot_projection(comparison.snapshot),
                         "unmatched_computers": sum(len(v) for k, v in comparison.reports.items()
                                                    if not comparison.server_counts[k]),
                         "ambiguous_computers": sum(len(v) for k, v in comparison.reports.items()
                                                    if comparison.server_counts[k] > 1 or len(v) > 1)})


class ServerUpdatesView(TenantUpdateView):
    @transaction.atomic
    def get(self, request, pk, server_id):
        source = get_object_or_404(UpdateSource.objects.select_for_update(), tenant=request.tenant, id=pk)
        comparison = Comparison(source)
        server = next((s for s in comparison.servers if s.id == server_id), None)
        if not server:
            raise PublicApiError("not_found", status_code=404)
        _, report = comparison.match(server)
        return Response(page(comparison.details(report, comparison.agent_evidence(server)), request))
