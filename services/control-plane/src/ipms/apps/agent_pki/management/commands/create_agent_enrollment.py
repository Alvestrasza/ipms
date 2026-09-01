import json
import os
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from ipms.apps.agent_pki.services import create_enrollment_token
from ipms.apps.tenancy.models import Tenant


class Command(BaseCommand):
    help = "Create one Agent enrollment and write its one-time bootstrap document securely."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--display-name", required=True)
        parser.add_argument("--output", required=True)
        parser.add_argument("--actor", required=True)
        parser.add_argument("--lifetime-minutes", type=int, default=30)

    def handle(self, *args, **options) -> None:
        output = Path(options["output"])
        if output.exists():
            raise CommandError("The enrollment output already exists.")
        try:
            tenant = Tenant.objects.get(slug=options["tenant_slug"])
            enrollment, token, gateway_fingerprint = create_enrollment_token(
                tenant=tenant,
                display_name=options["display_name"],
                actor=options["actor"],
                lifetime_minutes=options["lifetime_minutes"],
            )
            document = json.dumps(
                {
                    "device_uri": enrollment.device_uri,
                    "gateway_dns_name": tenant.agent_pki_policy.gateway_dns_name,
                    "gateway_port": tenant.agent_pki_policy.gateway_port,
                    "gateway_fingerprint_sha256": gateway_fingerprint,
                    "bootstrap_token": token,
                },
                separators=(",", ":"),
            ).encode()
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(document)
        except Tenant.DoesNotExist as exc:
            raise CommandError("The tenant does not exist.") from exc
        except OSError as exc:
            raise CommandError("The enrollment output could not be written.") from exc
        self.stdout.write(
            self.style.SUCCESS(
                "Enrollment created; the one-time bootstrap secret was written without printing it."
            )
        )
