from __future__ import annotations

from django.conf import settings
from django.db import models
from django.utils import timezone


class UserProfile(models.Model):
    ROLE_DEVELOPER = "Developer"
    ROLE_ADMIN = "Administrator"
    ROLE_MANAGER = "Manager"
    ROLE_DISTRIBUTOR = "Distributor"
    ROLE_AUDITOR = "Auditor"

    ROLE_CHOICES = [
        (ROLE_DEVELOPER, "Developer"),
        (ROLE_ADMIN, "Administrator"),
        (ROLE_MANAGER, "Manager"),
        (ROLE_DISTRIBUTOR, "Distributor"),
        (ROLE_AUDITOR, "Auditor"),
    ]

    MFA_TOTP = "totp"
    MFA_EMAIL = "email"
    MFA_CHOICES = [
        (MFA_TOTP, "Authenticator (TOTP)"),
        (MFA_EMAIL, "Email OTP"),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )

    # Email change flow tracking
    email_change_token_jti = models.CharField(max_length=64, blank=True, null=True)
    email_change_token_used_at = models.DateTimeField(blank=True, null=True)

    # --- Identity / Baseline profile ---
    display_name = models.CharField(max_length=120, blank=True, default="")
    contact_number = models.CharField(max_length=30, blank=True, default="")
    organization = models.CharField(max_length=150, blank=True, default="")
    avatar = models.ImageField(upload_to="avatars/", null=True, blank=True)

    # Immutable issued portal ID (stable even if role changes later)
    issued_prefix = models.CharField(max_length=16, blank=True, default="")
    issued_number = models.PositiveIntegerField(null=True, blank=True)

    # --- Security / MFA ---
    role = models.CharField(max_length=32, choices=ROLE_CHOICES, default=ROLE_DISTRIBUTOR)

    primary_mfa_method = models.CharField(
        max_length=10,
        choices=MFA_CHOICES,
        default=MFA_TOTP,
    )
    email_fallback_enabled = models.BooleanField(default=True)

    last_password_change_at = models.DateTimeField(null=True, blank=True)
    last_mfa_verified_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def public_id(self) -> str:
        """
        Example: ADMIN-0001
        If not issued yet, return empty string to avoid lying.
        """
        if not self.issued_prefix or not self.issued_number:
            return ""
        return f"{self.issued_prefix.upper()}-{self.issued_number:04d}"

    def __str__(self):
        return f"{self.user.email or self.user.username} ({self.role})"


class PasswordHistory(models.Model):
    """
    Store recent password hashes to prevent reuse.
    We only need the last 2 (your requirement).
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="password_history",
    )
    password_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [models.Index(fields=["user", "created_at"])]


class UserSession(models.Model):
    """
    Future-proof session tracking (device/IP list). You can populate gradually.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="user_sessions",
    )
    session_key = models.CharField(max_length=64, db_index=True)
    ip_address = models.CharField(max_length=64, blank=True, default="")
    user_agent = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "ended_at"]),
            models.Index(fields=["session_key"]),
        ]
