# portal/views.py
from __future__ import annotations
from portal.dashboard.views import dashboard
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
from .utils.recovery_codes import generate_plain_codes, replace_user_codes, verify_and_consume_code
from .models import MFARecoveryCode
from .decorators import admin_required
from django_otp import login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice
from portal.utils.security import issue_email_otp, verify_email_otp
from .decorators import admin_required
from portal.utils.security import audit
from .forms import EmailChangeForm
from .forms import (
    DistributorApplicationForm,
    PortalAuthenticationForm,
    UserCreateForm,
    UserEditForm,
)
from .models import DistributorApplication  # keep if used elsewhere
from portal.utils.security import get_notifications_for_user


from portal.users.views import (
    user_list,
    user_create,
    user_edit,
    user_reset_mfa,
)

from portal.auth.views import (
    PortalLoginView,
    PortalLogoutView,
    PortalPasswordResetView,
    PortalPasswordResetDoneView,
    PortalPasswordResetConfirmView,
    PortalPasswordResetCompleteView,
)


from portal.profile.views import (
    profile_settings,
    profile_recovery_codes,
    profile_stepup_verify,
    profile_email_change,
    profile_email_change_error,
)

from portal.mfa.views import (
    mfa_setup,
    mfa_verify,
    mfa_recovery,
    mfa_qr_png,
)



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
# Auth
# -------------------------
class PortalLoginView(LoginView):
    template_name = "portal/login.html"
    authentication_form = PortalAuthenticationForm


# -------------------------
# Users (admin-required)
# -------------------------
User = get_user_model()


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



@login_required
def mfa_recovery_codes(request):
    """
    Show/generate recovery codes. Show plaintext ONLY on generation.
    """
    if request.method == "POST":
        codes = generate_plain_codes(10)
        replace_user_codes(request.user, codes)
        return render(request, "portal/mfa_recovery_codes.html", {"codes": codes})

    return render(request, "portal/mfa_recovery_codes.html", {"codes": None})


@admin_required
def user_reset_recovery(request, user_id):
    user_obj = get_object_or_404(get_user_model(), id=user_id)
    if request.method == "POST":
        MFARecoveryCode.objects.filter(user=user_obj).delete()
        messages.success(request, f"Recovery codes reset for {user_obj.username}.")
        return redirect("portal:user_list")
    return render(request, "portal/users/user_reset_recovery_confirm.html", {"user_obj": user_obj})


def navbar_notifications(request):
    if not request.user.is_authenticated:
        return {"notifications": [], "notification_count": 0}

    items = get_notifications_for_user(request.user)
    return {
        "notifications": items,
        "notification_count": len(items),
    }



@login_required
def profile(request):
    """
    Profile page with tabs. Ensures email-change validation errors
    keep the user on the Security tab instead of redirecting to default tab.
    """

    # Default tab from URL (GET)
    active_tab = request.GET.get("tab", "general")

    # Forms (add other forms you already have here)
    email_form = EmailChangeForm(user=request.user)

    # Handle POST actions
    if request.method == "POST":
        action = request.POST.get("action", "")

        # EMAIL CHANGE (Security tab)
        if action == "change_email":
            email_form = EmailChangeForm(request.POST, user=request.user)

            if email_form.is_valid():
                new_email = email_form.cleaned_data["new_email"]

                # ---- your existing email change flow goes here ----
                # Example (adjust to your actual implementation):
                # request.user.pending_email = new_email
                # request.user.save(update_fields=["pending_email"])
                # send_verification_email(request.user, new_email)
                # ---------------------------------------------------

                messages.success(request, "Verification link sent to your new email address.")
                return redirect(f"{reverse('portal:profile')}?tab=security")

            # IMPORTANT: do NOT redirect on error
            # Re-render page and force Security tab active
            active_tab = "security"
            messages.error(request, "Please correct the error below.")

    return render(request, "portal/profile.html", {
        "active_tab": active_tab,
        "email_form": email_form,
        # include other forms your template expects:
        # "password_form": password_form,
        # "mfa_form": mfa_form,
    })