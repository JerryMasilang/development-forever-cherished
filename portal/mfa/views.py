# portal/mfa/views.py
import qrcode
from io import BytesIO

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.urls import reverse

from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp import login as otp_login

from portal.models import UserProfile
from portal.utils.security import issue_email_otp, verify_email_otp
from portal.utils.recovery_codes import verify_and_consume_code

DEVICE_NAME = "default"


# Session flag for EMAIL OTP verification (since django-otp verifies only via otp_login/device)
SESSION_MFA_VERIFIED = "portal_mfa_verified"

DASHBOARD_URL_NAME = "portal:dashboard:dashboard"



def _get_or_create_totp_device(user) -> TOTPDevice:
    device = TOTPDevice.objects.filter(user=user, name=DEVICE_NAME).first()
    if not device:
        device = TOTPDevice.objects.create(user=user, name=DEVICE_NAME, confirmed=False)
    return device


def _get_confirmed_totp_device(user) -> TOTPDevice | None:
    return TOTPDevice.objects.filter(user=user, name=DEVICE_NAME, confirmed=True).first()


@login_required
def mfa_setup(request):
    profile = request.user.profile
    device = _get_or_create_totp_device(request.user)

    if request.method == "POST":
        token = (request.POST.get("token") or "").strip()
        if device.verify_token(token):
            device.confirmed = True
            device.save(update_fields=["confirmed"])

            profile.primary_mfa_method = UserProfile.MFA_TOTP
            profile.last_mfa_verified_at = timezone.now()
            profile.save(update_fields=["primary_mfa_method", "last_mfa_verified_at"])

            otp_login(request, device)  # marks django-otp verified for this session
            request.session[SESSION_MFA_VERIFIED] = True  # also mark our own flag

            messages.success(request, "Authenticator successfully configured.")
            return redirect(DASHBOARD_URL_NAME)

        messages.error(request, "Invalid verification code.")

    return render(request, "portal/mfa_setup.html", {"provisioning_uri": device.config_url})


@login_required
def mfa_verify(request):
    """
    Login-time MFA verification screen.

    Supports:
    - TOTP (Authenticator) via django-otp (otp_login)
    - Email OTP fallback via cache-based OTP (issue_email_otp/verify_email_otp)
    """

    profile = request.user.profile

    # If already verified (django-otp OR our session flag), proceed
    otp_verified = getattr(request.user, "is_verified", lambda: False)()
    session_verified = bool(request.session.get(SESSION_MFA_VERIFIED))
    if otp_verified or session_verified:
        return redirect(DASHBOARD_URL_NAME)

    use = (request.GET.get("use") or "").strip().lower()

    fallback_enabled = bool(getattr(profile, "email_fallback_enabled", True)) and bool(request.user.email)
    has_totp = TOTPDevice.objects.filter(user=request.user, confirmed=True).exists()

    # Determine which method to show
    if use == "email":
        method = "email"
    elif use == "totp":
        method = "totp"
    else:
        method = "email" if profile.primary_mfa_method == UserProfile.MFA_EMAIL else "totp"

    # If user chose email but fallback isn't available, force totp
    if method == "email" and not fallback_enabled:
        method = "totp"

    # ✅ IMPORTANT: Only process verification on POST
    if request.method == "POST":

        # -------------------------
        # EMAIL: SEND OTP
        # -------------------------
        if method == "email" and (request.POST.get("action") or "").strip() == "send":
            try:
                issue_email_otp(request, request.user)
                messages.info(request, "We sent a verification code to your email.")
            except Exception as e:
                messages.error(request, str(e))
            return redirect(reverse("portal:mfa_verify") + "?use=email")

        # -------------------------
        # EMAIL: VERIFY OTP
        # -------------------------
        if method == "email" and request.POST.get("code") is not None:
            code = (request.POST.get("code") or "").strip()
            if verify_email_otp(request, request.user, code):
                profile.last_mfa_verified_at = timezone.now()
                profile.save(update_fields=["last_mfa_verified_at"])

                # Mark this session as verified (middleware will respect this)
                request.session[SESSION_MFA_VERIFIED] = True

                return redirect(DASHBOARD_URL_NAME)

            messages.error(request, "Invalid or expired email code.")
            return redirect(reverse("portal:mfa_verify") + "?use=email")

        # -------------------------
        # TOTP: VERIFY
        # -------------------------
        if method == "totp":
            token = (request.POST.get("token") or "").strip()
            device = _get_confirmed_totp_device(request.user)
            if not device:
                messages.info(request, "Please set up your authenticator app first.")
                return redirect("portal:mfa_setup")

            if device.verify_token(token):
                otp_login(request, device)
                profile.last_mfa_verified_at = timezone.now()
                profile.save(update_fields=["last_mfa_verified_at"])

                request.session[SESSION_MFA_VERIFIED] = True
                return redirect(DASHBOARD_URL_NAME)

            messages.error(request, "Invalid authenticator code.")
            return redirect(reverse("portal:mfa_verify") + "?use=totp")

    # ✅ GET: just render (NO redirects)
    return render(
        request,
        "portal/mfa_verify.html",
        {
            "method": method,
            "fallback_enabled": fallback_enabled,
            "has_totp": has_totp,
        },
    )


@login_required
def mfa_recovery(request):
    device = _get_confirmed_totp_device(request.user)

    if request.method == "POST":
        code = (request.POST.get("code") or "").strip()
        if verify_and_consume_code(request.user, code):
            if device:
                otp_login(request, device)

            request.user.profile.last_mfa_verified_at = timezone.now()
            request.user.profile.save(update_fields=["last_mfa_verified_at"])

            request.session[SESSION_MFA_VERIFIED] = True

            messages.success(request, "Recovery code accepted.")
            return redirect(DASHBOARD_URL_NAME)

        messages.error(request, "Invalid or already used recovery code.")

    return render(request, "portal/mfa_recovery.html")


@login_required
def mfa_qr_png(request):
    device = _get_or_create_totp_device(request.user)

    img = qrcode.make(device.config_url)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return HttpResponse(buffer.getvalue(), content_type="image/png")


# @login_required
# def mfa_recovery(request):
#     """
#     Use a recovery code instead of TOTP.
#     """
#     if request.method == "POST":
#         code = (request.POST.get("code") or "").strip()
#         if verify_and_consume_recovery_code(request.user, code):
#             # Satisfy OTP by attaching a confirmed device if it exists
#             device = TOTPDevice.objects.filter(user=request.user, confirmed=True).order_by("-id").first()
#             if device:
#                 otp_login(request, device)

#             audit(request, "MFA_RECOVERY_CODE_USED", target_user=request.user)
#             messages.success(request, "Recovery code accepted.")
#             return redirect("portal:dashboard:dashboard")

#         messages.error(request, "Invalid or already-used recovery code.")
#         return redirect("portal:mfa_recovery")

#     return render(request, "portal/mfa_recovery.html")
