from django.contrib import admin

from .models import ConnectorEndpoint, DiscoveryJob, PhysicalSystem


@admin.register(ConnectorEndpoint)
class ConnectorEndpointAdmin(admin.ModelAdmin):
    list_display = ("display_name", "tenant", "connector_type", "health", "enabled")
    list_filter = ("connector_type", "health", "enabled")
    search_fields = ("display_name", "base_url")
    exclude = ("credential_reference", "tls_certificate_sha256")


@admin.register(PhysicalSystem)
class PhysicalSystemAdmin(admin.ModelAdmin):
    list_display = ("name", "tenant", "model", "power_state", "health")
    list_filter = ("health", "power_state")
    search_fields = ("name", "model", "serial_number")
    readonly_fields = tuple(field.name for field in PhysicalSystem._meta.fields)

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


@admin.register(DiscoveryJob)
class DiscoveryJobAdmin(admin.ModelAdmin):
    list_display = ("created_at", "tenant", "connector_type", "status")
    list_filter = ("connector_type", "status")
    search_fields = ("requested_by", "correlation_id", "error_code")
    readonly_fields = tuple(field.name for field in DiscoveryJob._meta.fields)

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False
