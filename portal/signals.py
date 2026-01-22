from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model

# SYNC TEST: signals.py multi-file push test
# SYNC TEST: signals.py multi-file push test

from .models import UserProfile

User = get_user_model()


@receiver(post_save, sender=User)
def ensure_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
