# portal/utils/security.py
from __future__ import annotations

import hashlib
import secrets
import time
from datetime import timedelta
from typing import Iterable, List

from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils import timezone

from portal.models import MFARecoveryCode, AuditLog




def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def generate_recovery_codes(count: int = 10) -> List[str]:
    # Easy-to-type codes; adjust length if you want longer.
    # Example: "A1B2C3D4E5"
    return [secrets.token_hex(5).upper() for _ in range(count)]  # 10 hex chars


def replace_recovery_codes(user, plaintext_codes: Iterable[str]) -> None:
    MFARecoveryCode.objects.filter(user=user).delete()
    MFARecoveryCode.objects.bulk_create(
        [MFARecoveryCode(user=user, code_hash=sha256_hex(c)) for c in plaintext_codes]
    )


def verify_and_consume_recovery_code(user, code: str) -> bool:
    h = sha256_hex(code)
    obj = MFARecoveryCode.objects.filter(user=user, code_hash=h, used_at__isnull=True).first()
    if not obj:
        return False
    obj.used_at = timezone.now()
    obj.save(update_fields=["used_at"])
    return True


def get_client_ip(request) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "") or ""




# -------- Password reset rate limiting (Task 3 uses these) --------
def rate_limit_hit(key: str, limit: int, window_seconds: int) -> bool:
    """
    Returns True if the action should be blocked (limit exceeded).
    """
    current = cache.get(key)
    if current is None:
        cache.set(key, 1, window_seconds)
        return False
    if int(current) >= limit:
        return True
    cache.incr(key)
    return False


def _otp_cache_key(user_id: int) -> str:
    return f"mfa:email:otp:{user_id}"

def _otp_attempts_key(user_id: int) -> str:
    return f"mfa:email:attempts:{user_id}"

def issue_email_otp(request, user, ttl_seconds: int = 300) -> None:
    ip = get_client_ip(request) or "unknown"

    # Rate limit sends (per user + per IP)
    if rate_limit_hit(f"mfa_email_send:user:{user.id}", 5, 60 * 60):
        raise ValueError("Too many OTP requests. Try again later.")
    if rate_limit_hit(f"mfa_email_send:ip:{ip}", 20, 60 * 60):
        raise ValueError("Too many OTP requests from this network. Try again later.")

    if not user.email:
        raise ValueError("No email address is set for your account.")

    code = f"{secrets.randbelow(1_000_000):06d}"
    cache.set(_otp_cache_key(user.id), sha256_hex(code), ttl_seconds)
    cache.set(_otp_attempts_key(user.id), 0, ttl_seconds)

    subject = "Your Forever Cherished QR Portal verification code"
    message = (
        f"Your verification code is: {code}\n\n"
        f"This code expires in {ttl_seconds//60} minutes."
    )
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None)
    send_mail(subject, message, from_email, [user.email], fail_silently=False)

    audit(request, "MFA_EMAIL_OTP_SENT", target_user=user)

def verify_email_otp(request, user, code: str, max_attempts: int = 6) -> bool:
    stored = cache.get(_otp_cache_key(user.id))
    if not stored:
        return False

    attempts = int(cache.get(_otp_attempts_key(user.id)) or 0)
    if attempts >= max_attempts:
        audit(request, "MFA_EMAIL_OTP_LOCKED", target_user=user)
        return False

    cache.incr(_otp_attempts_key(user.id))
    ok = sha256_hex(code) == stored
    if ok:
        cache.delete(_otp_cache_key(user.id))
        cache.delete(_otp_attempts_key(user.id))
        audit(request, "MFA_EMAIL_OTP_VERIFIED", target_user=user)
    return ok



def step_up_mark_verified(request, purpose: str):
    ttl = getattr(settings, "STEP_UP_TTL_SECONDS", 300)
    request.session[f"stepup:{purpose}"] = int(time.time()) + ttl

def step_up_is_verified(request, purpose: str) -> bool:
    exp = request.session.get(f"stepup:{purpose}")
    if not exp:
        return False
    try:
        return int(exp) >= int(time.time())
    except Exception:
        return False

def step_up_clear(request, purpose: str):
    request.session.pop(f"stepup:{purpose}", None)

def email_otp_issue(request, purpose: str) -> str:
    """
    Generate OTP and store server-side in session.
    """
    ttl = getattr(settings, "EMAIL_OTP_TTL_SECONDS", 300)
    code = f"{secrets.randbelow(1000000):06d}"
    request.session[f"emailotp:{purpose}:code"] = code
    request.session[f"emailotp:{purpose}:exp"] = int(time.time()) + ttl
    request.session[f"emailotp:{purpose}:tries"] = 0
    return code

def email_otp_verify(request, purpose: str, code: str) -> bool:
    stored = request.session.get(f"emailotp:{purpose}:code")
    exp = request.session.get(f"emailotp:{purpose}:exp")
    tries = int(request.session.get(f"emailotp:{purpose}:tries") or 0)

    if tries >= 5:
        return False

    request.session[f"emailotp:{purpose}:tries"] = tries + 1

    if not stored or not exp:
        return False
    if int(exp) < int(time.time()):
        return False

    return (stored == (code or "").strip())

def email_otp_clear(request, purpose: str):
    request.session.pop(f"emailotp:{purpose}:code", None)
    request.session.pop(f"emailotp:{purpose}:exp", None)
    request.session.pop(f"emailotp:{purpose}:tries", None)


def audit(request, action: str, target_user=None, reason: str = "", meta=None):
    try:
        ip = get_client_ip(request) if request else None
        ua = ""
        if request:
            ua = (request.META.get("HTTP_USER_AGENT") or "")[:255]

        actor = getattr(request, "user", None)
        if actor and not getattr(actor, "is_authenticated", False):
            actor = None

        AuditLog.objects.create(
            actor=actor,
            target_user=target_user,
            action=action,
            ip=ip,
            ua=ua,
            reason=reason or "",
            meta=meta,
        )
    except Exception:
        # never block the request due to logging failures
        pass
    

NOTIFICATION_ACTIONS = {
    "PASSWORD_CHANGED",
    "MFA_RECOVERY_CODE_USED",
    "SESSION_TERMINATED",
    "OTHER_SESSIONS_TERMINATED",
    "STEPUP_TOTP_FAILED",
    "STEPUP_EMAIL_FAILED",
    "QR_ASSIGNED",
    "QR_RECEIVED",
    "DISTRIBUTOR_APPROVED",
    "DISTRIBUTOR_REJECTED",
}

def get_notifications_for_user(user, since_minutes=1440):
    """
    Return recent audit logs that qualify as notifications for this user.
    Default: last 24 hours.
    """
    since = timezone.now() - timedelta(minutes=since_minutes)

    qs = AuditLog.objects.filter(
        created_at__gte=since,
        action__in=NOTIFICATION_ACTIONS,
    )

    # Role-aware targeting
    role = getattr(getattr(user, "profile", None), "role", None)

    if role in {"Administrator", "Manager"}:
        # admins see all important events
        return qs.select_related("actor", "target_user")[:20]

    # Regular users only see events affecting them
    return qs.filter(
        target_user=user
    ).select_related("actor", "target_user")[:20]
