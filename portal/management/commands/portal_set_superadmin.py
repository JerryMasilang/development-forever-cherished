from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.db import transaction

from portal.models import UserProfile

User = get_user_model()


class Command(BaseCommand):
    help = "Assign the single SuperAdmin by email. Enforces exactly one SuperAdmin."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True, help="Email of the user to become SuperAdmin")

    @transaction.atomic
    def handle(self, *args, **options):
        email = (options["email"] or "").strip().lower()
        if not email:
            raise CommandError("Email is required.")

        try:
            user = User.objects.select_related("profile").get(email__iexact=email)
        except User.DoesNotExist:
            raise CommandError(f"User with email '{email}' not found.")

        profile = user.profile

        # Enforce exactly ONE superadmin
        existing = UserProfile.objects.filter(is_superadmin=True).exclude(user=user)
        if existing.exists():
            raise CommandError("A SuperAdmin already exists. Only one SuperAdmin is allowed.")

        profile.is_superadmin = True

        # Optional: keep SuperAdmin role as Administrator for UI grouping.
        # This does NOT grant extra governance powers; is_superadmin does.
        profile.role = UserProfile.ROLE_ADMIN

        profile.save(update_fields=["is_superadmin", "role", "updated_at"])

        self.stdout.write(self.style.SUCCESS(f"SuperAdmin set: {user.email}"))
