# portal/utils/recovery_codes.py
from __future__ import annotations

import hashlib
import secrets
from typing import Iterable, List

from django.utils import timezone

from portal.models import MFARecoveryCode


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()


def generate_plain_codes(n: int = 10) -> List[str]:
    # 10 chars base32-ish, easy to type; you can adjust length
    return [secrets.token_hex(4).upper() for _ in range(n)]  # 8 hex chars


def replace_user_codes(user, plain_codes: Iterable[str]) -> None:
    MFARecoveryCode.objects.filter(user=user, used_at__isnull=True).delete()
    MFARecoveryCode.objects.filter(user=user, used_at__isnull=False).delete()

    MFARecoveryCode.objects.bulk_create(
        [MFARecoveryCode(user=user, code_hash=_hash_code(c)) for c in plain_codes]
    )


def verify_and_consume_code(user, code: str) -> bool:
    h = _hash_code(code)
    rc = MFARecoveryCode.objects.filter(
        user=user, code_hash=h, used_at__isnull=True
    ).first()
    if not rc:
        return False
    rc.used_at = timezone.now()
    rc.save(update_fields=["used_at"])
    return True
