from __future__ import annotations

from django.conf import settings
from django.db import models
# from apps.portal.audit.models import AuditLog



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


class AuditLog(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        related_name="audit_actor",
        on_delete=models.SET_NULL,
    )

    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
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
