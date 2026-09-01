from django.contrib import admin

from .models import (
    BmcCommunicationLog,
    BmcEventLogEntry,
    ConnectorEndpoint,
    DiscoveryJob,
    PhysicalSystem,
    WindowsServer,
    WindowsServerTelemetry,
)


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


@admin.register(WindowsServer)
class WindowsServerAdmin(admin.ModelAdmin):
    list_display = (
        "hostname",
        "tenant",
        "server_type",
        "inventory_source",
        "agent_state",
        "health",
    )
    list_filter = ("server_type", "inventory_source", "agent_state", "health")
    search_fields = ("hostname", "fqdn", "domain_name", "cluster_name")
    readonly_fields = tuple(field.name for field in WindowsServer._meta.fields)

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


@admin.register(WindowsServerTelemetry)
class WindowsServerTelemetryAdmin(admin.ModelAdmin):
    list_display = ("server", "tenant", "cpu_used_percent", "memory_used_percent", "observed_at")
    readonly_fields = tuple(field.name for field in WindowsServerTelemetry._meta.fields)

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


@admin.register(BmcCommunicationLog)
class BmcCommunicationLogAdmin(admin.ModelAdmin):
    list_display = ("occurred_at", "tenant", "bmc_name", "severity", "event_type")
    list_filter = ("severity", "bmc_family", "event_type")
    search_fields = (
        "bmc_name",
        "resource_path",
        "error_code",
        "redfish_message_id",
    )
    readonly_fields = tuple(field.name for field in BmcCommunicationLog._meta.fields)

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


@admin.register(BmcEventLogEntry)
class BmcEventLogEntryAdmin(admin.ModelAdmin):
    list_display = (
        "source_created_at",
        "tenant",
        "bmc_name",
        "log_type",
        "severity",
    )
    list_filter = ("log_type", "severity", "repaired")
    search_fields = ("bmc_name", "message", "source_record_id")
    readonly_fields = tuple(field.name for field in BmcEventLogEntry._meta.fields)

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False
