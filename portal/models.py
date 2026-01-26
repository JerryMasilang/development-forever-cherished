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

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
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



class UserEventAudit(models.Model):
    ACTION_CREATE = "CREATE"
    ACTION_ROLE_CHANGE = "ROLE_CHANGE"
    ACTION_ACTIVATE = "ACTIVATE"
    ACTION_DEACTIVATE = "DEACTIVATE"
    ACTION_MFA_RESET = "MFA_RESET"

    ACTION_CHOICES = [
        (ACTION_CREATE, "Create user"),
        (ACTION_ROLE_CHANGE, "Role change"),
        (ACTION_ACTIVATE, "Activate user"),
        (ACTION_DEACTIVATE, "Deactivate user"),
        (ACTION_MFA_RESET, "Reset MFA"),
    ]

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="user_audits_as_actor",
    )
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="user_audits_as_target",
    )

    action = models.CharField(max_length=32, choices=ACTION_CHOICES)

    from_role = models.CharField(max_length=32, blank=True, default="")
    to_role = models.CharField(max_length=32, blank=True, default="")
    reason = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)


class DistributorApplication(models.Model):
    full_name = models.CharField(max_length=150)
    email = models.EmailField()
    mobile = models.CharField(max_length=30, blank=True)
    company_name = models.CharField(max_length=150, blank=True)
    location = models.CharField(max_length=150, blank=True)
    notes = models.TextField(blank=True)

    status = models.CharField(
        max_length=30, default="Pending"
    )  # Pending/Approved/Rejected
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - {self.email} ({self.status})"


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


class AuditLog(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        related_name="audit_actor",
        on_delete=models.SET_NULL,
    )

    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True,
        related_name="audit_target",
        on_delete=models.SET_NULL,
    )

    action = models.CharField(max_length=64, db_index=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    ua = models.CharField(max_length=255, blank=True, default="")
    reason = models.CharField(max_length=255, blank=True, default="")
    meta = models.JSONField(blank=True, null=True)

    class Meta:
        ordering = ["-created_at"]
