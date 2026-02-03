# portal/users/services.py
from __future__ import annotations

from django.contrib.auth import get_user_model
from django_otp.plugins.otp_totp.models import TOTPDevice

from portal.models import MFARecoveryCode
from portal.utils.security import audit

User = get_user_model()


def list_users():
    return User.objects.all().order_by("username")


def create_user(form):
    """
    form: UserCreateForm (already validated outside OR we validate inside)
    """
    return form.save()


def update_user(form):
    return form.save()


def reset_user_mfa(user_obj):
    """
    Deletes all TOTP devices so user must re-enroll on next login.
    """
    TOTPDevice.objects.filter(user=user_obj).delete()


def reset_user_recovery_codes(request, user_obj):
    """
    Deletes recovery codes and writes audit log.
    """
    MFARecoveryCode.objects.filter(user=user_obj).delete()
    audit(request, "RESET_RECOVERY_CODES", target_user=user_obj)
