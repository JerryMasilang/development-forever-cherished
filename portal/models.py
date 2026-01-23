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
    MFA_TOTP = "totp"
    MFA_EMAIL = "email"
    MFA_CHOICES = [
        (MFA_TOTP, "Authenticator (TOTP)"),
        (MFA_EMAIL, "Email OTP"),
    ]

    primary_mfa_method = models.CharField(
        max_length=10,
        choices=MFA_CHOICES,
        default=MFA_TOTP,
    )
    email_fallback_enabled = models.BooleanField(default=True)

    ROLE_CHOICES = [
        (ROLE_DEVELOPER, "Developer"),
        (ROLE_ADMIN, "Administrator"),
        (ROLE_MANAGER, "Manager"),
        (ROLE_DISTRIBUTOR, "Distributor"),
        (ROLE_AUDITOR, "Auditor"),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile"
    )
    role = models.CharField(
        max_length=32, choices=ROLE_CHOICES, default=ROLE_DISTRIBUTOR
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email or self.user.username} ({self.role})"


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
    Stores hashed recovery codes. Never store plaintext codes.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="mfa_recovery_codes")
    code_hash = models.CharField(max_length=128, db_index=True)  # sha256 hex length = 64, but keep room
    created_at = models.DateTimeField(default=timezone.now)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "used_at"]),
        ]

    @property
    def is_used(self) -> bool:
        return self.used_at is not None
    


class MFARecoveryCode(models.Model):
    """
    Hashed recovery codes (never store plaintext).
    Each code is single-use.
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
    """
    Lightweight audit log for admin actions and security-relevant events.
    """
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )
    action = models.CharField(max_length=120)  # e.g. "RESET_MFA", "RESET_RECOVERY_CODES"
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs_as_target",
    )
    reason = models.TextField(blank=True)
    ip_address = models.CharField(max_length=64, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.action}"