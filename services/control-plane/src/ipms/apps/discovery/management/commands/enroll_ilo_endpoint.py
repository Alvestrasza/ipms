import json
import re

from django.core.management.base import BaseCommand, CommandError

from ipms.apps.discovery.models import ConnectorEndpoint
from ipms.apps.tenancy.models import Tenant


SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class Command(BaseCommand):
    help = "Enroll or update a tenant-owned iLO Redfish endpoint without a secret."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--display-name", required=True)
        parser.add_argument("--base-url", required=True)
        parser.add_argument("--certificate-sha256", required=True)

    def handle(self, *args, **options) -> None:
        fingerprint = options["certificate_sha256"].replace(":", "").lower()
        if not SHA256_PATTERN.fullmatch(fingerprint):
            raise CommandError("The certificate SHA-256 fingerprint is invalid.")
        try:
            tenant = Tenant.objects.get(slug=options["tenant_slug"])
        except Tenant.DoesNotExist as exc:
            raise CommandError("The selected tenant does not exist.") from exc
        endpoint, created = ConnectorEndpoint.objects.update_or_create(
            tenant=tenant,
            base_url=options["base_url"],
            defaults={
                "display_name": options["display_name"],
                "connector_type": ConnectorEndpoint.ConnectorType.ILO_REDFISH,
                "tls_certificate_sha256": fingerprint,
                "enabled": True,
            },
        )
        self.stdout.write(
            json.dumps(
                {
                    "endpoint_id": str(endpoint.id),
                    "credential_reference": str(endpoint.credential_reference),
                    "created": created,
                },
                separators=(",", ":"),
            )
        )
