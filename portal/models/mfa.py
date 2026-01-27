from __future__ import annotations

from django.conf import settings
from django.db import models
from django.utils import timezone


class MFARecoveryCode(models.Model):
    """
    Hashed recovery codes (never store plaintext). Each code is single-use.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="mfa_recovery_codes",
    )
    code_hash = models.CharField(max_length=128, db_index=True)
    created_at = models.DateTimeField(default=timezone.now)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["user", "used_at"])]

    @property
    def is_used(self) -> bool:
        return self.used_at is not None
