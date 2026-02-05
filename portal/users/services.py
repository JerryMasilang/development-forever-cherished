# portal/users/services.py
from __future__ import annotations

from django.contrib.auth import get_user_model
from django_otp.plugins.otp_totp.models import TOTPDevice
from portal.models import MFARecoveryCode
from portal.utils.security import audit


from django.db import transaction
from django.utils import timezone
from django.core.exceptions import PermissionDenied, ValidationError
from portal.models import UserProfile, AuditLog



User = get_user_model()


@transaction.atomic
def set_account_status(*, actor, target, new_status: str, reason: str = ""):
    prof = target.profile

    if new_status not in dict(UserProfile.STATUS_CHOICES):
        raise ValidationError("Invalid account status.")

    # Enforce reason for governance actions (suspend/deactivate/pending)
    requires_reason = new_status in {
        UserProfile.STATUS_INACTIVE,
        UserProfile.STATUS_SUSPENDED,
        UserProfile.STATUS_PENDING,
    }
    if requires_reason and not (reason or "").strip():
        raise ValidationError("Reason is required.")

    prof.account_status = new_status
    prof.status_updated_at = timezone.now()

    # sync with Django auth gate
    if new_status == UserProfile.STATUS_ACTIVE:
        target.is_active = True
        prof.suspended_at = None
        prof.suspended_reason = ""
        audit(None, "USER_ACTIVATED", target_user=target, reason=(reason or ""))

    elif new_status == UserProfile.STATUS_INACTIVE:
        target.is_active = False
        prof.suspended_at = None
        prof.suspended_reason = ""
        audit(None, "USER_DEACTIVATED", target_user=target, reason=(reason or ""))

    elif new_status == UserProfile.STATUS_PENDING:
        target.is_active = False
        prof.suspended_at = None
        prof.suspended_reason = ""
        audit(None, "USER_SET_PENDING", target_user=target, reason=(reason or ""))

    elif new_status == UserProfile.STATUS_SUSPENDED:
        target.is_active = False
        prof.suspended_at = timezone.now()
        prof.suspended_reason = (reason or "").strip()[:255]
        audit(None, "USER_SUSPENDED", target_user=target, reason=prof.suspended_reason)

    target.save(update_fields=["is_active"])
    prof.save(update_fields=[
        "account_status", "status_updated_at",
        "suspended_at", "suspended_reason",
    ])

    # Also record actor-aware audit row (preferred)
    audit_obj_reason = (reason or "")[:255]
    from portal.models import AuditLog
    AuditLog.objects.create(
        actor=actor,
        target_user=target,
        action=f"USER_STATUS_{new_status.upper()}",
        reason=audit_obj_reason,
        meta={"new_status": new_status},
    )




def list_users():
    return User.objects.all().order_by("username")


def create_user(form):
    """
    form: UserCreateForm (already validated outside OR we validate inside)
    """
    return form.save()


def update_user(form):
    return form.save()


def reset_user_mfa(user_obj):
    """
    Deletes all TOTP devices so user must re-enroll on next login.
    """
    TOTPDevice.objects.filter(user=user_obj).delete()


def reset_user_recovery_codes(request, user_obj):
    """
    Deletes recovery codes and writes audit log.
    """
    MFARecoveryCode.objects.filter(user=user_obj).delete()
    audit(request, "RESET_RECOVERY_CODES", target_user=user_obj)


def _profile(user):
    return getattr(user, "profile", None)

def _is_superadmin(user) -> bool:
    return bool(getattr(_profile(user), "is_superadmin", False))

def _role(user) -> str:
    return str(getattr(_profile(user), "role", "") or "")

def _is_admin(user) -> bool:
    return _role(user) == UserProfile.ROLE_ADMIN

def _count_active_admins(exclude_user_id=None) -> int:
    qs = User.objects.filter(is_active=True, profile__role=UserProfile.ROLE_ADMIN)
    if exclude_user_id:
        qs = qs.exclude(id=exclude_user_id)
    return qs.count()

def _count_superadmins() -> int:
    return UserProfile.objects.filter(is_superadmin=True).count()

def _ensure_single_superadmin(new_superadmin_user: User):
    # Enforce exactly ONE superadmin in production (app-level constraint).
    existing = UserProfile.objects.filter(is_superadmin=True).exclude(user=new_superadmin_user)
    if existing.exists():
        raise ValidationError("A SuperAdmin already exists. Only one SuperAdmin is allowed.")




def guard_user_admin_action(*, actor: User, target: User, action: str):
    actor_prof = _profile(actor)
    target_prof = _profile(target)

    actor_is_super = bool(getattr(actor_prof, "is_superadmin", False))
    target_is_super = bool(getattr(target_prof, "is_superadmin", False))
    target_is_admin = _is_admin(target)

    if actor.id == target.id:
        raise PermissionDenied("You cannot perform this action on your own account.")

    if target_is_super:
        raise PermissionDenied("SuperAdmin account cannot be modified.")

    if (not actor_is_super) and target_is_admin:
        raise PermissionDenied("Only SuperAdmin can manage Administrator accounts.")


@transaction.atomic
def deactivate_user(*, actor: User, target: User, reason: str):
    if not reason or not reason.strip():
        raise ValidationError("Reason is required.")

    guard_user_admin_action(actor=actor, target=target, action="DEACTIVATE")

    # Prevent removing last remaining admin
    if _is_admin(target) and _count_active_admins(exclude_user_id=target.id) == 0:
        raise ValidationError("You cannot deactivate the last remaining Administrator.")

    target.is_active = False
    target.save(update_fields=["is_active"])

    # Your system already has AuditLog and UserEventAudit; use either or both.
    AuditLog.objects.create(
        actor=actor,
        target_user=target,
        action="USER_DEACTIVATED",
        reason=reason[:255],
        meta={"target_role": _role(target)},
    )

@transaction.atomic
def change_user_role(*, actor: User, target: User, new_role: str, reason: str):
    if not reason or not reason.strip():
        raise ValidationError("Reason is required.")

    if new_role not in dict(UserProfile.ROLE_CHOICES):
        raise ValidationError("Invalid role.")

    guard_user_admin_action(actor=actor, target=target, action="ROLE_CHANGE")

    prof = target.profile
    old_role = prof.role

    # additional protection: if target is admin and actor isn't superadmin
    if (not _is_superadmin(actor)) and (old_role == UserProfile.ROLE_ADMIN or new_role == UserProfile.ROLE_ADMIN):
        raise PermissionDenied("Only SuperAdmin can assign or change Administrator roles.")

    prof.role = new_role
    prof.save(update_fields=["role", "updated_at"])

    AuditLog.objects.create(
        actor=actor,
        target_user=target,
        action="USER_ROLE_CHANGED",
        reason=reason[:255],
        meta={"from_role": old_role, "to_role": new_role},
    )

def reset_user_mfa(*, actor: User, target: User, reason: str):
    if not reason or not reason.strip():
        raise ValidationError("Reason is required.")
    guard_user_admin_action(actor=actor, target=target, action="MFA_RESET")

    TOTPDevice.objects.filter(user=target).delete()

    AuditLog.objects.create(
        actor=actor,
        target_user=target,
        action="USER_MFA_RESET",
        reason=reason[:255],
        meta={"target_role": _role(target)},
    )


def reset_user_recovery_codes(*, actor: User, target: User, reason: str):
    if not reason or not reason.strip():
        raise ValidationError("Reason is required.")
    guard_user_admin_action(actor=actor, target=target, action="RESET_RECOVERY_CODES")

    MFARecoveryCode.objects.filter(user=target).delete()

    AuditLog.objects.create(
        actor=actor,
        target_user=target,
        action="RESET_RECOVERY_CODES",
        reason=reason[:255],
        meta={"target_role": _role(target)},
    )
