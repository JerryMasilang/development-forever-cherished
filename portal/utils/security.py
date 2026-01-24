# portal/utils/security.py
from __future__ import annotations

import hashlib
import secrets
from typing import Iterable, List, Optional
from django.core.cache import cache
from django.utils import timezone
from portal.models import MFARecoveryCode, AuditLog
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
import time


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


def audit(request, action: str, target_user=None, reason: str = "") -> None:
    try:
        AuditLog.objects.create(
            actor=getattr(request, "user", None) if getattr(request, "user", None) and request.user.is_authenticated else None,
            action=action,
            target_user=target_user,
            reason=reason or "",
            ip_address=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "") or "",
        )
    except Exception:
        # Never block the user flow because of logging errors
        pass


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