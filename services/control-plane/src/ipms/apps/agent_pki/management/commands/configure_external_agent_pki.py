from django.core.management.base import BaseCommand, CommandError

from ipms.apps.agent_pki.services import (
    configure_external_certificate_pki,
    configure_external_issuing_pki,
)
from ipms.apps.tenancy.models import Tenant
from ipms.apps.agent_pki.management.protected_files import read_protected_file


class Command(BaseCommand):
    help = "Configure a tenant Agent PKI from explicitly supplied protected external files."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--mode",
            required=True,
            choices=("external_issuing_ca", "external_certificates"),
        )
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--gateway-dns-name", required=True)
        parser.add_argument("--issuer-certificate")
        parser.add_argument("--issuer-private-key")
        parser.add_argument("--issuer-chain")
        parser.add_argument("--gateway-certificate")
        parser.add_argument("--gateway-private-key")
        parser.add_argument("--gateway-chain")
        parser.add_argument("--private-key-passphrase-file")
        parser.add_argument("--actor", required=True)

    def handle(self, *args, **options) -> None:
        try:
            tenant = Tenant.objects.get(slug=options["tenant_slug"])
            password = (
                read_protected_file(options["private_key_passphrase_file"]).strip()
                if options["private_key_passphrase_file"]
                else None
            )
            if options["mode"] == "external_issuing_ca":
                required = ("issuer_certificate", "issuer_private_key", "issuer_chain")
                if any(not options[name] for name in required):
                    raise CommandError("External issuing CA files are incomplete.")
                configure_external_issuing_pki(
                    tenant=tenant,
                    gateway_dns_name=options["gateway_dns_name"],
                    issuer_certificate_pem=read_protected_file(options["issuer_certificate"]),
                    issuer_private_key_pem=read_protected_file(options["issuer_private_key"]),
                    issuer_private_key_password=password,
                    chain_pem=read_protected_file(options["issuer_chain"]),
                    actor=options["actor"],
                )
            else:
                required = (
                    "issuer_certificate",
                    "gateway_certificate",
                    "gateway_private_key",
                    "gateway_chain",
                )
                if any(not options[name] for name in required):
                    raise CommandError("External Gateway or Agent trust files are incomplete.")
                configure_external_certificate_pki(
                    tenant=tenant,
                    gateway_dns_name=options["gateway_dns_name"],
                    gateway_certificate_pem=read_protected_file(options["gateway_certificate"]),
                    gateway_private_key_pem=read_protected_file(options["gateway_private_key"]),
                    gateway_private_key_password=password,
                    gateway_chain_pem=read_protected_file(options["gateway_chain"]),
                    agent_issuer_certificate_pem=read_protected_file(options["issuer_certificate"]),
                    actor=options["actor"],
                )
        except Tenant.DoesNotExist as exc:
            raise CommandError("The tenant does not exist.") from exc
        except OSError as exc:
            raise CommandError("An external PKI input file could not be read.") from exc
        self.stdout.write(
            self.style.SUCCESS(
                "External Agent PKI material validated and imported without printing it."
            )
        )
