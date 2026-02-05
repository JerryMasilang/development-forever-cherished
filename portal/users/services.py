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
    # Phase 2: guard FIRST (prevents last-admin lockout + superadmin/admin protections)
    guard_governance_action(
        actor=actor,
        target=target,
        action=GOV_ACTION_STATUS,
        new_status=new_status,
    )

    prof = target.profile

    # Reason enforcement (keep your existing rule)
    requires_reason = new_status in {
        UserProfile.STATUS_INACTIVE,
        UserProfile.STATUS_SUSPENDED,
        UserProfile.STATUS_PENDING,
    }
    if requires_reason and not (reason or "").strip():
        raise ValidationError("Reason is required.")

    prof.account_status = new_status
    prof.status_updated_at = timezone.now()

    if new_status == UserProfile.STATUS_ACTIVE:
        target.is_active = True
        prof.suspended_at = None
        prof.suspended_reason = ""

    elif new_status == UserProfile.STATUS_INACTIVE:
        target.is_active = False
        prof.suspended_at = None
        prof.suspended_reason = ""

    elif new_status == UserProfile.STATUS_PENDING:
        target.is_active = False
        prof.suspended_at = None
        prof.suspended_reason = ""

    elif new_status == UserProfile.STATUS_SUSPENDED:
        target.is_active = False
        prof.suspended_at = timezone.now()
        prof.suspended_reason = (reason or "").strip()[:255]

    target.save(update_fields=["is_active"])
    prof.save(update_fields=[
        "account_status", "status_updated_at",
        "suspended_at", "suspended_reason",
    ])

    AuditLog.objects.create(
        actor=actor,
        target_user=target,
        action=f"USER_STATUS_{new_status.upper()}",
        reason=(reason or "")[:255],
        meta={"new_status": new_status, "target_role": _role(target)},
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




# portal/users/services.py
from django.core.exceptions import PermissionDenied, ValidationError

GOV_ACTION_STATUS = "STATUS_CHANGE"
GOV_ACTION_ROLE = "ROLE_CHANGE"
GOV_ACTION_MFA_RESET = "MFA_RESET"
GOV_ACTION_RECOVERY_RESET = "RECOVERY_RESET"

def _is_governance_admin(user) -> bool:
    p = _profile(user)
    return bool(p and (p.is_superadmin or p.role == UserProfile.ROLE_ADMIN))

def log_blocked_governance_attempt(*, actor: User, target: User, action: str, message: str, meta=None):
    # Optional but very useful
    AuditLog.objects.create(
        actor=actor,
        target_user=target,
        action="GOV_BLOCKED",
        reason=message[:255],
        meta={"attempted_action": action, **(meta or {})},
    )

def guard_governance_action(
    *,
    actor: User,
    target: User,
    action: str,
    new_status: str | None = None,
    new_role: str | None = None,
):
    actor_p = _profile(actor)
    target_p = _profile(target)

    if not actor_p or not target_p:
        raise PermissionDenied("Profile missing.")

    actor_is_super = bool(actor_p.is_superadmin)
    target_is_super = bool(target_p.is_superadmin)
    target_is_admin = (target_p.role == UserProfile.ROLE_ADMIN)

    # 1) No self-governance actions
    if actor.id == target.id:
        raise PermissionDenied("You cannot perform governance actions on your own account.")

    # 2) Nobody can modify SuperAdmin
    if target_is_super:
        raise PermissionDenied("SuperAdmin account cannot be modified.")

    # 3) Only SuperAdmin can manage Administrators (any governance action)
    if target_is_admin and not actor_is_super:
        raise PermissionDenied("Only SuperAdmin can manage Administrator accounts.")

    # 4) Role assignment protection (Admin role is SuperAdmin-only)
    if action == GOV_ACTION_ROLE:
        if not new_role:
            raise ValidationError("new_role is required.")
        if new_role not in dict(UserProfile.ROLE_CHOICES):
            raise ValidationError("Invalid role.")

        # If changing to/from Administrator, only SuperAdmin may do it
        if (target_p.role == UserProfile.ROLE_ADMIN) or (new_role == UserProfile.ROLE_ADMIN):
            if not actor_is_super:
                raise PermissionDenied("Only SuperAdmin can assign or change Administrator roles.")

        # Prevent “last admin” lockout via role change (strongly recommended)
        if target_p.role == UserProfile.ROLE_ADMIN and new_role != UserProfile.ROLE_ADMIN:
            if _count_active_admins(exclude_user_id=target.id) == 0:
                raise ValidationError("You cannot remove the last remaining Administrator.")

    # 5) Status change protection + last admin lockout
    if action == GOV_ACTION_STATUS:
        if not new_status:
            raise ValidationError("new_status is required.")
        if new_status not in dict(UserProfile.STATUS_CHOICES):
            raise ValidationError("Invalid account status.")

        # Prevent last active admin from being suspended/deactivated/pending
        if target_is_admin and new_status in {
            UserProfile.STATUS_INACTIVE,
            UserProfile.STATUS_SUSPENDED,
            UserProfile.STATUS_PENDING,
        }:
            if _count_active_admins(exclude_user_id=target.id) == 0:
                raise ValidationError("You cannot disable the last remaining Administrator.")



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

    guard_governance_action(actor=actor, target=target, action=GOV_ACTION_MFA_RESET)

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

    guard_governance_action(actor=actor, target=target, action=GOV_ACTION_RECOVERY_RESET)

    MFARecoveryCode.objects.filter(user=target).delete()

    AuditLog.objects.create(
        actor=actor,
        target_user=target,
        action="RESET_RECOVERY_CODES",
        reason=reason[:255],
        meta={"target_role": _role(target)},
    )




