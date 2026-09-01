from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from ipms.apps.agent_pki.services import export_gateway_runtime
from ipms.apps.tenancy.models import Tenant


class Command(BaseCommand):
    help = "Materialize one tenant Gateway TLS identity into a protected runtime directory."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--directory", required=True)

    def handle(self, *args, **options) -> None:
        try:
            tenant = Tenant.objects.get(slug=options["tenant_slug"])
            export_gateway_runtime(tenant=tenant, directory=Path(options["directory"]))
        except Tenant.DoesNotExist as exc:
            raise CommandError("The tenant does not exist.") from exc
        self.stdout.write(self.style.SUCCESS("Agent Gateway runtime material exported."))
