from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from ipms.apps.agent_pki.models import AgentEnrollment, AgentGatewayIdentity, AgentIssuer


class Command(BaseCommand):
    help = "Check Agent PKI certificate expiry without exposing certificate material."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--warning-days", type=int, default=14)

    def handle(self, *args, **options) -> None:
        if not 1 <= options["warning_days"] <= 90:
            raise CommandError("Warning days must be between 1 and 90.")
        threshold = timezone.now() + timedelta(days=options["warning_days"])
        counts = {
            "gateway_identities": AgentGatewayIdentity.objects.filter(
                not_after__lte=threshold
            ).count(),
            "accepted_issuers": AgentIssuer.objects.filter(
                status__in=(AgentIssuer.Status.ACTIVE, AgentIssuer.Status.OVERLAP),
                not_after__lte=threshold,
            ).count(),
            "active_agents": AgentEnrollment.objects.filter(
                status=AgentEnrollment.Status.ACTIVE,
                certificate_not_after__lte=threshold,
            ).count(),
        }
        self.stdout.write(
            "Agent PKI expiry summary: "
            + ", ".join(f"{name}={count}" for name, count in counts.items())
        )
        if any(counts.values()):
            raise CommandError("One or more Agent PKI identities require attention.")
