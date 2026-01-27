from django.contrib import messages
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404, redirect, render

from django_otp.plugins.otp_totp.models import TOTPDevice

from portal.decorators import admin_required
from portal.forms import UserCreateForm, UserEditForm
from portal.models import MFARecoveryCode
from portal.utils.security import audit

User = get_user_model()


@admin_required
def user_list(request):
    users = User.objects.all().order_by("username")
    return render(request, "portal/users/user_list.html", {"users": users})


@admin_required
def user_create(request):
    if request.method == "POST":
        form = UserCreateForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "User created successfully.")
            return redirect("portal:user_list")
    else:
        form = UserCreateForm()

    return render(
        request, "portal/users/user_form.html", {"form": form, "mode": "create"}
    )


@admin_required
def user_edit(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        form = UserEditForm(request.POST, instance=user_obj)
        if form.is_valid():
            form.save()
            messages.success(request, "User updated successfully.")
            return redirect("portal:user_list")
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
        if not reason:
            messages.error(request, "Reason is required.")
            return redirect("portal:user_reset_mfa", user_id=user_obj.id)

        TOTPDevice.objects.filter(user=user_obj).delete()
        audit(request, "RESET_MFA", target_user=user_obj, reason=reason)

        messages.success(
            request,
            f"MFA reset for {user_obj.username}. They must re-enroll on next login.",
        )
        return redirect("portal:user_list")

    return render(
        request, "portal/users/user_reset_mfa_confirm.html", {"user_obj": user_obj}
    )


@admin_required
def user_reset_recovery(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        reason = (request.POST.get("reason") or "").strip()
        if not reason:
            messages.error(request, "Reason is required.")
            return redirect("portal:user_reset_recovery", user_id=user_obj.id)

        MFARecoveryCode.objects.filter(user=user_obj).delete()
        audit(request, "RESET_RECOVERY_CODES", target_user=user_obj, reason=reason)

        messages.success(request, f"Recovery codes reset for {user_obj.username}.")
        return redirect("portal:user_list")

    return render(
        request,
        "portal/users/user_reset_recovery_confirm.html",
        {"user_obj": user_obj},
    )
