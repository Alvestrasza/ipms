from django.core.management.base import BaseCommand, CommandError

from ipms.apps.agent_pki.management.protected_files import read_protected_file
from ipms.apps.agent_pki.services import import_external_agent_certificate
from ipms.apps.tenancy.models import Tenant


class Command(BaseCommand):
    help = "Import one pre-issued Agent certificate in external-certificate mode."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--display-name", required=True)
        parser.add_argument("--certificate", required=True)
        parser.add_argument("--actor", required=True)

    def handle(self, *args, **options) -> None:
        try:
            tenant = Tenant.objects.get(slug=options["tenant_slug"])
            import_external_agent_certificate(
                tenant=tenant,
                display_name=options["display_name"],
                certificate_pem=read_protected_file(options["certificate"]),
                actor=options["actor"],
            )
        except Tenant.DoesNotExist as exc:
            raise CommandError("The tenant does not exist.") from exc
        except OSError as exc:
            raise CommandError("The external Agent certificate could not be read.") from exc
        self.stdout.write(
            self.style.SUCCESS("External Agent certificate validated and imported.")
        )
