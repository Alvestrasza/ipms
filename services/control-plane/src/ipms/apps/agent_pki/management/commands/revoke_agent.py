from django.core.management.base import BaseCommand, CommandError

from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.agent_pki.services import revoke_agent


class Command(BaseCommand):
    help = "Immediately revoke one enrolled Agent identity."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--device-uri", required=True)
        parser.add_argument("--reason", required=True)
        parser.add_argument("--actor", required=True)

    def handle(self, *args, **options) -> None:
        try:
            enrollment = AgentEnrollment.objects.get(
                tenant__slug=options["tenant_slug"],
                device_uri=options["device_uri"],
            )
        except AgentEnrollment.DoesNotExist as exc:
            raise CommandError("The Agent enrollment does not exist.") from exc
        revoke_agent(
            enrollment=enrollment,
            actor=options["actor"],
            reason=options["reason"],
        )
        self.stdout.write(self.style.SUCCESS("Agent identity revoked."))
