# File Name: export_agent_gateway_runtime.py
# Version: v0.2.76 | Last Modified: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Materialize one or all tenant Gateway TLS identities.
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from ipms.apps.agent_pki.services import export_all_gateway_runtime, export_gateway_runtime
from ipms.apps.tenancy.models import Tenant


class Command(BaseCommand):
    help = "Materialize tenant-isolated Gateway TLS identities into a protected runtime directory."

    def add_arguments(self, parser) -> None:
        selection = parser.add_mutually_exclusive_group(required=True)
        selection.add_argument("--tenant-slug")
        selection.add_argument("--all-tenants", action="store_true")
        parser.add_argument("--directory", required=True)

    def handle(self, *args, **options) -> None:
        try:
            if options["all_tenants"]:
                manifest = export_all_gateway_runtime(directory=Path(options["directory"]))
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Agent Gateway runtime material exported for {len(manifest['tenants'])} tenants."
                    )
                )
                return
            tenant = Tenant.objects.get(slug=options["tenant_slug"])
            export_gateway_runtime(tenant=tenant, directory=Path(options["directory"]))
        except Tenant.DoesNotExist as exc:
            raise CommandError("The tenant does not exist.") from exc
        self.stdout.write(self.style.SUCCESS("Agent Gateway runtime material exported."))
