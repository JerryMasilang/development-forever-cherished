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