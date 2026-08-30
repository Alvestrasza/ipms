from django.contrib import admin

from .models import Tenant, TenantMembership


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ("slug", "display_name", "status", "created_at")
    list_filter = ("status",)
    search_fields = ("slug", "display_name", "external_reference")
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(TenantMembership)
class TenantMembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "tenant", "role", "is_active", "created_at")
    list_filter = ("role", "is_active")
    search_fields = ("user__username", "tenant__slug", "tenant__display_name")
    readonly_fields = ("id", "created_at", "updated_at")
