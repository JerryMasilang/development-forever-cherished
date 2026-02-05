# portal/users/views.py
from __future__ import annotations

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth import get_user_model

from portal.decorators import admin_required
from portal.forms import UserCreateForm, UserEditForm
from portal.users import services
from django.core.exceptions import ValidationError,PermissionDenied
from django.utils import timezone
from portal.utils.security import audit
from portal.models import UserProfile
User = get_user_model()




@admin_required
def user_list(request):
    users = services.list_users()
    return render(request, "portal/users/user_list.html", {"users": users})


@admin_required
def user_create(request):
    if request.method == "POST":
        form = UserCreateForm(request.POST)
        if form.is_valid():
            services.create_user(form)
            messages.success(request, "User created successfully.")
            return redirect("portal:users:user_list")
    else:
        form = UserCreateForm()

    return render(request, "portal/users/user_form.html", {"form": form, "mode": "create"})







from django.core.exceptions import PermissionDenied, ValidationError

@admin_required
def user_edit(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        form = UserEditForm(request.POST, instance=user_obj)
        reason = (request.POST.get("reason") or "").strip()

        if form.is_valid():
            try:
                old_role = getattr(user_obj.profile, "role", None)
                new_role = form.proposed_role() or old_role

                if new_role != old_role and not reason:
                    raise ValidationError("Reason is required for role changes.")

                # Phase 2: if role changes, run governance service (guard + audit)
                if new_role != old_role:
                    services.change_user_role(
                        actor=request.user,
                        target=user_obj,
                        new_role=new_role,
                        reason=reason,
                    )

                # Save remaining non-governance fields
                form.save()

                messages.success(request, "User updated successfully.")
                return redirect("portal:users:user_list")

            except (ValidationError, PermissionDenied) as e:
                messages.error(request, str(e))

    else:
        form = UserEditForm(instance=user_obj)

    return render(
        request,
        "portal/users/user_form.html",
        {"form": form, "mode": "edit", "user_obj": user_obj},
    )


@admin_required
def user_reset_mfa(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        reason = (request.POST.get("reason") or "").strip()
        try:
            services.reset_user_mfa(actor=request.user, target=user_obj, reason=reason)
            messages.success(request, f"MFA reset for {user_obj.username}. They must re-enroll on next login.")
            return redirect("portal:users:user_list")
        except (ValidationError, PermissionDenied) as e:
            messages.error(request, str(e))

    return render(request, "portal/users/user_reset_mfa_confirm.html", {"user_obj": user_obj})


from django.core.exceptions import ValidationError, PermissionDenied
from portal.models import UserProfile

@admin_required
def user_activate(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        reason = (request.POST.get("reason") or "").strip()
        try:
            services.guard_user_admin_action(actor=request.user, target=user_obj, action="ACTIVATE")
            services.set_account_status(actor=request.user, target=user_obj, new_status=UserProfile.STATUS_ACTIVE, reason=reason)
            messages.success(request, f"{user_obj.username} activated.")
            return redirect("portal:users:user_list")
        except (ValidationError, PermissionDenied) as e:
            messages.error(request, str(e))

    return render(request, "portal/users/user_status_confirm.html", {
        "user_obj": user_obj,
        "action_label": "Activate User",
        "action_color": "success",
        "help_text": "This will allow the user to log in again.",
        "reason_required": False,
    })


@admin_required
def user_deactivate(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        reason = (request.POST.get("reason") or "").strip()
        try:
            services.guard_user_admin_action(actor=request.user, target=user_obj, action="DEACTIVATE")
            services.set_account_status(actor=request.user, target=user_obj, new_status=UserProfile.STATUS_INACTIVE, reason=reason)
            messages.success(request, f"{user_obj.username} deactivated.")
            return redirect("portal:users:user_list")
        except (ValidationError, PermissionDenied) as e:
            messages.error(request, str(e))

    return render(request, "portal/users/user_status_confirm.html", {
        "user_obj": user_obj,
        "action_label": "Deactivate User",
        "action_color": "secondary",
        "help_text": "This will block login (inactive).",
        "reason_required": True,
    })


@admin_required
def user_suspend(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        reason = (request.POST.get("reason") or "").strip()
        try:
            services.guard_user_admin_action(actor=request.user, target=user_obj, action="SUSPEND")
            services.set_account_status(actor=request.user, target=user_obj, new_status=UserProfile.STATUS_SUSPENDED, reason=reason)
            messages.success(request, f"{user_obj.username} suspended.")
            return redirect("portal:users:user_list")
        except (ValidationError, PermissionDenied) as e:
            messages.error(request, str(e))

    return render(request, "portal/users/user_status_confirm.html", {
        "user_obj": user_obj,
        "action_label": "Suspend User",
        "action_color": "danger",
        "help_text": "Suspension blocks login and records a suspension reason.",
        "reason_required": True,
    })


@admin_required
def user_set_pending(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        reason = (request.POST.get("reason") or "").strip()
        try:
            services.guard_user_admin_action(actor=request.user, target=user_obj, action="SET_PENDING")
            services.set_account_status(actor=request.user, target=user_obj, new_status=UserProfile.STATUS_PENDING, reason=reason)
            messages.success(request, f"{user_obj.username} set to pending.")
            return redirect("portal:users:user_list")
        except (ValidationError, PermissionDenied) as e:
            messages.error(request, str(e))

    return render(request, "portal/users/user_status_confirm.html", {
        "user_obj": user_obj,
        "action_label": "Set Pending",
        "action_color": "warning",
        "help_text": "Pending blocks login until activated by an admin.",
        "reason_required": True,
    })




@admin_required
def user_reset_recovery(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        reason = (request.POST.get("reason") or "").strip()
        try:
            services.reset_user_recovery_codes(
                actor=request.user,
                target=user_obj,
                reason=reason,
            )
            messages.success(request, f"Recovery codes reset for {user_obj.username}.")
            return redirect("portal:users:user_list")
        except (ValidationError, PermissionDenied) as e:
            messages.error(request, str(e))

    return render(
        request,
        "portal/users/user_reset_recovery_confirm.html",
        {"user_obj": user_obj},
    )
