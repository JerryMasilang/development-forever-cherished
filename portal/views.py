# portal/views.py
from __future__ import annotations

from io import BytesIO

import qrcode
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from django_otp import login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice

from .decorators import admin_required
from .forms import (
    DistributorApplicationForm,
    PortalAuthenticationForm,
    UserCreateForm,
    UserEditForm,
)
from .models import DistributorApplication  # keep if used elsewhere


# -------------------------
# Dashboard
# -------------------------
@login_required
def dashboard(request):
    kpi = {
        "available": 0,
        "reserved": 0,
        "assigned": 0,
        "distributed": 0,
        "registered": 0,
        "total_generated": 0,
    }
    alerts = []
    return render(request, "portal/dashboard.html", {"kpi": kpi, "alerts": alerts})


# -------------------------
# QR utilities (prototype)
# -------------------------
def _public_base() -> str:
    # Add this in settings.py (see patch below)
    return getattr(settings, "PUBLIC_SITE_BASE_URL", "").rstrip("/")


def _make_public_urls(qr_id: str, status: str, memorial_slug: str | None = None):
    base = _public_base()
    qr_redirect_url = f"{base}/q/{qr_id}"
    enroll_url = f"{base}/enroll/{qr_id}"
    memorial_url = f"{base}/memorial/{memorial_slug}/" if memorial_slug else None

    if status == "REGISTERED" and memorial_url:
        display_url = memorial_url
        display_url_label = "Memorial"
    else:
        display_url = enroll_url
        display_url_label = "Enroll"

    return qr_redirect_url, enroll_url, memorial_url, display_url, display_url_label


def _compute_effective_status(custodian_enabled: bool, admin_override_status: str):
    if admin_override_status == "active":
        return "active"
    if admin_override_status == "inactive":
        return "inactive"
    return "active" if custodian_enabled else "inactive"


@login_required
def qr_png(request, qr_id: str):
    """
    Returns a PNG QR image encoding the stable redirect link.
    Works in prototype mode (no DB needed).
    """
    qr_url = f"{_public_base()}/q/{qr_id}"
    img = qrcode.make(qr_url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return HttpResponse(buf.getvalue(), content_type="image/png")


@login_required
def qr_control_center(request):
    """
    UI prototype: placeholder QR list + computed URLs + memorial activation controls.
    Database models are not yet implemented, so all values are derived from sample dicts.
    """

    # TEMP role gating (replace with your real role system later)
    user_role = getattr(getattr(request.user, "profile", None), "role", None)
    can_change_status = user_role in ["Administrator", "Manager"]

    qrs = [
        {
            "item_no": "0001",
            "id_code": "FC-5555",
            "status": "AVAILABLE",
            "memorial_of": None,
            "qr_id": "FC-9F2A1C3D",
            "custodian_name": None,
            "custodian_id": None,
            "enrollment_key_masked": "********",
            "assigned_to": None,
            "date_generated": "2026-01-20 15:10",
            "date_registered": None,
            "date_assigned": None,
            "custodian_enabled": True,
            "admin_override_status": "none",
            "admin_locked": False,
        },
        {
            "item_no": "0002",
            "id_code": "FC-5532",
            "status": "RESERVED",
            "memorial_of": None,
            "qr_id": "FC-1A7C8B2E",
            "custodian_name": None,
            "custodian_id": None,
            "enrollment_key_masked": "********",
            "assigned_to": None,
            "date_generated": "2026-01-20 15:10",
            "date_registered": None,
            "date_assigned": None,
            "custodian_enabled": True,
            "admin_override_status": "none",
            "admin_locked": False,
        },
        {
            "item_no": "0003",
            "id_code": "FC-5531",
            "status": "ASSIGNED",
            "memorial_of": None,
            "qr_id": "FC-7D3E2A19",
            "custodian_name": None,
            "custodian_id": None,
            "enrollment_key_masked": "********",
            "assigned_to": "ABC Funeral Services",
            "date_generated": "2026-01-18 10:20",
            "date_registered": None,
            "date_assigned": "2026-01-18 10:25",
            "custodian_enabled": True,
            "admin_override_status": "none",
            "admin_locked": False,
        },
        {
            "item_no": "0004",
            "id_code": "FC-5554",
            "status": "DISTRIBUTED",
            "memorial_of": None,
            "qr_id": "FC-4B8C2D1A",
            "custodian_name": None,
            "custodian_id": None,
            "enrollment_key_masked": "********",
            "assigned_to": "XYZ Lapida Maker",
            "date_generated": "2026-01-16 09:00",
            "date_registered": None,
            "date_assigned": "2026-01-16 09:10",
            "custodian_enabled": True,
            "admin_override_status": "none",
            "admin_locked": False,
        },
        {
            "item_no": "0005",
            "id_code": "FC-5558",
            "status": "REGISTERED",
            "memorial_of": "Fernando Masilang",
            "qr_id": "FC-0C1A9E2B",
            "custodian_name": "Jerry Masilang",
            "custodian_id": "98374",
            "enrollment_key_masked": "********",
            "assigned_to": "XYZ Lapida Maker",
            "date_generated": "2026-01-15 08:00",
            "date_registered": "2026-01-16 12:30",
            "date_assigned": "2026-01-15 08:10",
            "memorial_slug": "fernando-masilang",
            "custodian_enabled": True,
            "admin_override_status": "none",
            "admin_locked": False,
        },
    ]

    for row in qrs:
        (
            qr_redirect_url,
            enroll_url,
            memorial_url,
            display_url,
            display_url_label,
        ) = _make_public_urls(row["qr_id"], row["status"], row.get("memorial_slug"))

        row["qr_redirect_url"] = qr_redirect_url
        row["enroll_url"] = enroll_url
        row["memorial_url"] = memorial_url
        row["display_url"] = display_url
        row["display_url_label"] = display_url_label

        row["effective_status"] = _compute_effective_status(
            row.get("custodian_enabled", True),
            row.get("admin_override_status", "none"),
        )

    distributors = ["ABC Funeral Services", "XYZ Lapida Maker", "Guardian Partner"]

    return render(
        request,
        "portal/qr_control_center.html",
        {
            "qrs": qrs,
            "distributors": distributors,
            "can_change_status": can_change_status,
        },
    )


# -------------------------
# MFA
# -------------------------
@login_required
def mfa_setup(request):
    confirmed_device = (
        TOTPDevice.objects.filter(user=request.user, confirmed=True).order_by("-id").first()
    )

    if confirmed_device:
        return render(request, "portal/mfa_setup.html", {"mode": "verify"})

    device = (
        TOTPDevice.objects.filter(user=request.user, confirmed=False).order_by("-id").first()
    )
    if device is None:
        device = TOTPDevice.objects.create(user=request.user, name="default", confirmed=False)

    return render(
        request,
        "portal/mfa_setup.html",
        {
            "mode": "setup",
            "qr_url": reverse("portal:mfa_qr_png"),
        },
    )


@login_required
def mfa_verify(request):
    if request.method == "POST":
        token = request.POST.get("token", "").strip()
        device = (
            TOTPDevice.objects.filter(user=request.user, confirmed=True).order_by("-id").first()
            or TOTPDevice.objects.filter(user=request.user, confirmed=False).order_by("-id").first()
        )

        if not device:
            messages.error(request, "No authenticator is set up yet.")
            return redirect("portal:mfa_setup")

        if device.verify_token(token):
            if not device.confirmed:
                device.confirmed = True
                device.save(update_fields=["confirmed"])

            otp_login(request, device)
            messages.success(request, "Authenticator verified.")
            return redirect("portal:dashboard")

        messages.error(request, "Invalid code. Please try again.")
        return redirect("portal:mfa_setup")

    return redirect("portal:mfa_setup")


@login_required
def mfa_qr_png(request):
    device = TOTPDevice.objects.filter(user=request.user, confirmed=False).order_by("-id").first()
    if device is None:
        device = TOTPDevice.objects.create(user=request.user, name="default", confirmed=False)

    uri = device.config_url
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return HttpResponse(buf.getvalue(), content_type="image/png")


# -------------------------
# Auth
# -------------------------
class PortalLoginView(LoginView):
    template_name = "portal/login.html"
    authentication_form = PortalAuthenticationForm


# -------------------------
# Users (admin-required)
# -------------------------
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

    return render(request, "portal/users/user_form.html", {"form": form, "mode": "create"})


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
        TOTPDevice.objects.filter(user=user_obj).delete()
        messages.success(request, f"MFA reset for {user_obj.username}. They must re-enroll on next login.")
        return redirect("portal:user_list")

    return render(request, "portal/users/user_reset_mfa_confirm.html", {"user_obj": user_obj})


# -------------------------
# Distributor application
# -------------------------
def distributor_apply(request):
    if request.method == "POST":
        form = DistributorApplicationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Application submitted. We will contact you once reviewed.")
            return redirect("portal:login")
    else:
        form = DistributorApplicationForm()

    return render(request, "portal/auth/distributor_apply.html", {"form": form})
