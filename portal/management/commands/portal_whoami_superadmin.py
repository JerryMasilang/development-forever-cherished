from django.core.management.base import BaseCommand
from portal.models import UserProfile

class Command(BaseCommand):
    help = "Show current SuperAdmin account (if any)."

    def handle(self, *args, **kwargs):
        qs = UserProfile.objects.filter(is_superadmin=True).select_related("user")
        if not qs.exists():
            self.stdout.write("No SuperAdmin set.")
            return
        for p in qs:
            self.stdout.write(f"SuperAdmin: {p.user.email or p.user.username}")
