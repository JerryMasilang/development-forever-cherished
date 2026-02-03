# portal/users/views.py
from __future__ import annotations

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth import get_user_model

from portal.decorators import admin_required
from portal.forms import UserCreateForm, UserEditForm
from portal.users import services

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


@admin_required
def user_edit(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        form = UserEditForm(request.POST, instance=user_obj)
        if form.is_valid():
            services.update_user(form)
            messages.success(request, "User updated successfully.")
            return redirect("portal:users:user_list")
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
        services.reset_user_mfa(user_obj)
        messages.success(
            request,
            f"MFA reset for {user_obj.username}. They must re-enroll on next login.",
        )
        return redirect("portal:users:user_list")

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
