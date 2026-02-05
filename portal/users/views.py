# portal/users/views.py
from __future__ import annotations

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth import get_user_model

from portal.decorators import admin_required
from portal.forms import UserCreateForm, UserEditForm
from portal.users import services
from django.core.exceptions import ValidationError,PermissionDenied


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
                old_active = bool(user_obj.is_active)

                new_role = form.proposed_role() or old_role
                new_active = form.proposed_is_active()

                # Governance actions require reason only when triggered
                governance_change = (new_role != old_role) or (old_active and not new_active)
                if governance_change and not reason:
                    raise ValidationError("Reason is required for role changes or deactivation.")

                if new_role != old_role:
                    services.change_user_role(
                        actor=request.user,
                        target=user_obj,
                        new_role=new_role,
                        reason=reason,
                    )

                if old_active and (new_active is False):
                    services.deactivate_user(
                        actor=request.user,
                        target=user_obj,
                        reason=reason,
                    )

                # Save non-governance fields safely (email, mfa prefs)
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

# @admin_required
# def user_edit(request, user_id):
#     user_obj = get_object_or_404(User, id=user_id)

#     if request.method == "POST":
#         form = UserEditForm(request.POST, instance=user_obj)
#         reason = (request.POST.get("reason") or "").strip()

#         if form.is_valid():
#             try:
#                 # Snapshot current state BEFORE saving
#                 old_role = getattr(user_obj.profile, "role", None)
#                 old_active = bool(user_obj.is_active)

#                 # Pull proposed state from the form
#                 new_role = form.cleaned_data.get("role", old_role)
#                 new_active = bool(form.cleaned_data.get("is_active", old_active))

#                 # 1) Role change (governed)
#                 if new_role != old_role:
#                     services.change_user_role(
#                         actor=request.user,
#                         target=user_obj,
#                         new_role=new_role,
#                         reason=reason,
#                     )

#                 # 2) Deactivate (governed)
#                 if old_active and (new_active is False):
#                     services.deactivate_user(
#                         actor=request.user,
#                         target=user_obj,
#                         reason=reason,
#                     )

#                 # Optional: (if you want re-activate later)
#                 # If you do implement activate, create services.activate_user with guards.

#                 # 3) Save non-governance fields
#                 # IMPORTANT: Prevent form.save() from overriding role/is_active directly.
#                 # Save user fields (username/email) and profile non-governance fields.
#                 # If your UserEditForm is already handling profile fields, keep using it,
#                 # but be careful not to override role and is_active.

#                 # safest default:
#                 updated_user = form.save(commit=False)
#                 # enforce governed state:
#                 updated_user.is_active = user_obj.is_active
#                 updated_user.save(update_fields=["username", "email", "is_active"])

#                 # If form also saves profile fields, call it explicitly if present.
#                 # (Depends on your form implementation.)
#                 if hasattr(form, "save_profile"):
#                     form.save_profile()
#                 elif hasattr(form, "save_m2m"):
#                     form.save_m2m()

#                 messages.success(request, "User updated successfully.")
#                 return redirect("portal:users:user_list")

#             except (ValidationError, PermissionDenied) as e:
#                 messages.error(request, str(e))

#         # fallthrough: invalid form or errors
#     else:
#         form = UserEditForm(instance=user_obj)

#     return render(
#         request,
#         "portal/users/user_form.html",
#         {"form": form, "mode": "edit", "user_obj": user_obj},
#     )



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


@admin_required
def user_reset_recovery(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        services.reset_user_recovery_codes(request, user_obj)
        messages.success(request, f"Recovery codes reset for {user_obj.username}.")
        return redirect("portal:users:user_list")

    return render(
        request,
        "portal/users/user_reset_recovery_confirm.html",
        {"user_obj": user_obj},
    )
