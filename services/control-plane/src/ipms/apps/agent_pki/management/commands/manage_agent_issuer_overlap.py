import uuid

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from ipms.apps.agent_pki.services import rollback_managed_issuer, retire_overlap_issuer
from ipms.apps.tenancy.models import Tenant


class Command(BaseCommand):
    help = "Roll back to or safely retire an overlapping managed Agent issuer."

    def add_arguments(self, parser) -> None:
        parser.add_argument("action", choices=("rollback", "retire"))
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--issuer-id", required=True)
        parser.add_argument("--actor", required=True)

    def handle(self, *args, **options) -> None:
        try:
            tenant = Tenant.objects.get(slug=options["tenant_slug"])
            issuer_id = uuid.UUID(options["issuer_id"])
            operation = (
                rollback_managed_issuer
                if options["action"] == "rollback"
                else retire_overlap_issuer
            )
            issuer = operation(
                tenant=tenant,
                issuer_id=issuer_id,
                actor=options["actor"],
            )
        except (ValueError, Tenant.DoesNotExist, ValidationError) as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(
            self.style.SUCCESS(f"Agent issuer {options['action']} completed: {issuer.id}")
        )
