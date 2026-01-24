from __future__ import annotations
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.utils import timezone
from .models import UserProfile, PasswordHistory

User = get_user_model()

ROLE_PREFIX_MAP = {
    "Developer": "DEV",
    "Administrator": "ADMIN",
    "Manager": "MANAGER",
    "Distributor": "DIST",
    "Auditor": "AUDITOR",
}


def _next_issued_number(prefix: str) -> int:
    last = (
        UserProfile.objects.filter(issued_prefix=prefix)
        .exclude(issued_number__isnull=True)
        .order_by("-issued_number")
        .first()
    )
    return (last.issued_number or 0) + 1 if last else 1


@receiver(post_save, sender=User)
def ensure_profile(sender, instance, created, **kwargs):
    if created:
        profile = UserProfile.objects.create(user=instance)

        # Issue a stable portal ID once (based on initial role)
        prefix = ROLE_PREFIX_MAP.get(profile.role, "USER")
        profile.issued_prefix = prefix
        profile.issued_number = _next_issued_number(prefix)
        profile.save(update_fields=["issued_prefix", "issued_number"])


@receiver(pre_save, sender=User)
def password_change_email_alert(sender, instance: User, **kwargs):
    if not instance.pk:
        return
    try:
        old = User.objects.get(pk=instance.pk)
    except User.DoesNotExist:
        return

    if old.password != instance.password:
        # Track password change date + password history (last 2 enforced in form)
        if hasattr(instance, "profile"):
            instance.profile.last_password_change_at = timezone.now()
            instance.profile.save(update_fields=["last_password_change_at"])

        PasswordHistory.objects.create(user=instance, password_hash=instance.password)
        # keep last 2 only
        qs = PasswordHistory.objects.filter(user=instance).order_by("-created_at")
        for extra in qs[2:]:
            extra.delete()

        # Email alert (existing behavior)
        if not instance.email:
            return
        subject = "Your Forever Cherished portal password was changed"
        when = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
        body = (
            f"Hello,\n\n"
            f"This is a security notification that your portal password was changed.\n\n"
            f"Time: {when}\n\n"
            f"If you did not do this, please contact your administrator immediately.\n"
        )
        send_mail(
            subject,
            body,
            getattr(settings, "DEFAULT_FROM_EMAIL", None) or "no-reply@forevercherished.online",
            [instance.email],
            fail_silently=True,
        )