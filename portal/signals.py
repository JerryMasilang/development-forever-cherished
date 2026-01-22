from __future__ import annotations

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.utils import timezone
from django.db.models.signals import post_save




from .models import UserProfile

User = get_user_model()


@receiver(post_save, sender=User)
def ensure_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)



@receiver(pre_save, sender=User)
def password_change_email_alert(sender, instance: User, **kwargs):
    """
    If password hash changes, send an alert email.
    Note: This triggers for both "change password" and "reset password".
    """
    if not instance.pk:
        return

    try:
        old = User.objects.get(pk=instance.pk)
    except User.DoesNotExist:
        return

    if old.password != instance.password:
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