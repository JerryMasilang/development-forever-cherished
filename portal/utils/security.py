# portal/utils/security.py
from __future__ import annotations

import hashlib
import secrets
from typing import Iterable, List, Optional

from django.core.cache import cache
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
