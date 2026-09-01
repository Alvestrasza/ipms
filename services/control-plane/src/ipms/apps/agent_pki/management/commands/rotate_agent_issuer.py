from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from ipms.apps.agent_pki.services import rotate_managed_issuer
from ipms.apps.agent_pki.management.protected_files import read_protected_file
from ipms.apps.tenancy.models import Tenant


class Command(BaseCommand):
    help = "Rotate a managed tenant Agent issuer by using the offline Root recovery bundle."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--root-recovery-bundle", required=True)
        parser.add_argument("--root-recovery-passphrase-file", required=True)
        parser.add_argument("--actor", required=True)

    def handle(self, *args, **options) -> None:
        try:
            tenant = Tenant.objects.get(slug=options["tenant_slug"])
            bundle = read_protected_file(options["root_recovery_bundle"])
            passphrase = read_protected_file(
                options["root_recovery_passphrase_file"]
            ).strip()
            issuer = rotate_managed_issuer(
                tenant=tenant,
                recovery_bundle=bundle,
                recovery_passphrase=passphrase,
                actor=options["actor"],
            )
        except (OSError, Tenant.DoesNotExist, ValidationError) as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(f"Agent issuer rotated: {issuer.id}"))
