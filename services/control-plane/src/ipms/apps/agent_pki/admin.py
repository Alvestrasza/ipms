from django.contrib import admin

from .models import (
    AgentEnrollment,
    AgentEnrollmentToken,
    AgentGatewayIdentity,
    AgentIssuer,
    AgentPkiPolicy,
    AgentRevocation,
    WindowsAgentDeployment,
    WindowsAgentDeploymentSecret,
)


class ReadOnlyAgentPkiAdmin(admin.ModelAdmin):
    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


@admin.register(AgentPkiPolicy)
class AgentPkiPolicyAdmin(ReadOnlyAgentPkiAdmin):
    list_display = ("tenant", "trust_mode", "gateway_dns_name", "gateway_port")
    exclude = ("root_certificate_pem",)


@admin.register(AgentIssuer)
class AgentIssuerAdmin(ReadOnlyAgentPkiAdmin):
    list_display = ("tenant", "status", "external", "not_after")
    exclude = (
        "certificate_pem",
        "chain_pem",
        "private_key_nonce",
        "private_key_ciphertext",
    )


@admin.register(AgentGatewayIdentity)
class AgentGatewayIdentityAdmin(ReadOnlyAgentPkiAdmin):
    list_display = ("tenant", "fingerprint_sha256", "not_after")
    exclude = (
        "certificate_pem",
        "chain_pem",
        "private_key_nonce",
        "private_key_ciphertext",
    )


@admin.register(AgentEnrollment)
class AgentEnrollmentAdmin(ReadOnlyAgentPkiAdmin):
    list_display = ("display_name", "tenant", "device_uri", "status", "last_seen_at")
    exclude = ("certificate_pem",)


@admin.register(AgentEnrollmentToken)
class AgentEnrollmentTokenAdmin(ReadOnlyAgentPkiAdmin):
    list_display = ("enrollment", "tenant", "expires_at", "used_at", "created_by")
    exclude = ("token_digest", "gateway_fingerprint_sha256")


@admin.register(AgentRevocation)
class AgentRevocationAdmin(ReadOnlyAgentPkiAdmin):
    list_display = ("enrollment", "tenant", "reason", "revoked_at", "revoked_by")


@admin.register(WindowsAgentDeployment)
class WindowsAgentDeploymentAdmin(ReadOnlyAgentPkiAdmin):
    list_display = (
        "display_name",
        "tenant",
        "target_address",
        "status",
        "created_at",
    )


@admin.register(WindowsAgentDeploymentSecret)
class WindowsAgentDeploymentSecretAdmin(ReadOnlyAgentPkiAdmin):
    list_display = ("deployment", "tenant", "created_at")
    exclude = ("nonce", "ciphertext")
