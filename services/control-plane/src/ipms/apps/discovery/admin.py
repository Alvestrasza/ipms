from django.contrib import admin

from .models import DiscoveryJob


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
