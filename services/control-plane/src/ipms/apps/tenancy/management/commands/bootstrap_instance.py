from pathlib import Path

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.views.decorators.debug import sensitive_variables

from ipms.apps.tenancy.models import PlatformAdministrator, Tenant, TenantMembership


class Command(BaseCommand):
    help = "Create the first IPMS tenant and platform administrator idempotently."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--tenant-name", required=True)
        parser.add_argument("--admin-username", required=True)
        parser.add_argument("--admin-password-file", required=True)

    @sensitive_variables()
    @transaction.atomic
    def handle(self, *args, **options) -> None:
        password_path = Path(options["admin_password_file"])
        try:
            password = password_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise CommandError(
                "The administrator password file cannot be read."
            ) from exc
        if not password:
            raise CommandError("The administrator password file is empty.")

        tenant, _ = Tenant.objects.get_or_create(
            slug=options["tenant_slug"],
            defaults={"display_name": options["tenant_name"]},
        )
        user_model = get_user_model()
        user, created = user_model.objects.get_or_create(
            username=options["admin_username"],
        )
        if created:
            validate_password(password, user=user)
            user.set_password(password)
            user.is_active = True
            user.is_staff = False
            user.is_superuser = False
            user.save()
            PlatformAdministrator.objects.create(user=user)
        elif (
            not PlatformAdministrator.objects.filter(user=user).exists()
            or not user.is_active
            or user.is_staff
            or user.is_superuser
            or TenantMembership.objects.filter(user=user).exists()
        ):
            raise CommandError(
                "The bootstrap username is already assigned to another identity; no privileges were changed."
            )
        self.stdout.write(
            self.style.SUCCESS(
                "IPMS instance bootstrap completed; no password was printed."
            )
        )
