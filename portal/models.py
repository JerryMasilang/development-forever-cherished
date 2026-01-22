from django.conf import settings
from django.db import models


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
