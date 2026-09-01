import os
import secrets
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from ipms.apps.agent_pki.services import bootstrap_managed_pki
from ipms.apps.agent_pki.models import AgentPkiPolicy
from ipms.apps.agent_pki.management.protected_files import read_protected_file
from ipms.apps.tenancy.models import Tenant


class Command(BaseCommand):
    help = "Create a tenant Agent PKI and export encrypted Root recovery material once."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--gateway-dns-name", required=True)
        parser.add_argument("--root-recovery-output", required=True)
        parser.add_argument("--root-recovery-passphrase-file", required=True)
        parser.add_argument("--generate-root-recovery-passphrase", action="store_true")
        parser.add_argument("--actor", default="appliance-bootstrap")
        parser.add_argument("--if-missing", action="store_true")

    def handle(self, *args, **options) -> None:
        try:
            tenant = Tenant.objects.get(slug=options["tenant_slug"])
            if options["if_missing"] and AgentPkiPolicy.objects.filter(tenant=tenant).exists():
                self.stdout.write("Agent PKI already exists; bootstrap was not repeated.")
                return
            passphrase_path = Path(options["root_recovery_passphrase_file"])
            if options["generate_root_recovery_passphrase"]:
                descriptor = os.open(
                    passphrase_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                    stream.write(secrets.token_urlsafe(48))
                    stream.write("\n")
            passphrase = read_protected_file(passphrase_path).strip()
            output = Path(options["root_recovery_output"])
            if output.exists():
                raise CommandError("The Root recovery output already exists.")
            bootstrap_managed_pki(
                tenant=tenant,
                gateway_dns_name=options["gateway_dns_name"],
                recovery_output=output,
                recovery_passphrase=passphrase,
                actor=options["actor"],
            )
        except Tenant.DoesNotExist as exc:
            raise CommandError("The tenant does not exist.") from exc
        except OSError as exc:
            raise CommandError("The Root recovery input or output could not be accessed.") from exc
        self.stdout.write(
            self.style.SUCCESS(
                "Agent PKI created; encrypted Root recovery material was written once."
            )
        )
