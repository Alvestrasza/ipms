from django.contrib import admin

from .models import Tenant


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ("slug", "display_name", "status", "created_at")
    list_filter = ("status",)
    search_fields = ("slug", "display_name", "external_reference")
    readonly_fields = ("id", "created_at", "updated_at")
