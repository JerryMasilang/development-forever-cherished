from django.contrib import messages
from django.utils import timezone

from portal.utils.recovery_codes import (
    generate_plain_codes,
    replace_user_codes,
)
from portal.models import MFARecoveryCode


def regenerate_recovery_codes(request, user):
    """
    Regenerate MFA recovery codes for the logged-in user.
    """
    plain_codes = generate_plain_codes()
    replace_user_codes(user, plain_codes)

    messages.success(
        request,
        "New recovery codes generated. Store them in a safe place."
    )

    return plain_codes


def mark_email_change_failed(request, reason=None):
    """
    Generic helper for email-change failures.
    """
    messages.error(
        request,
        reason or "Email verification failed or expired."
    )
