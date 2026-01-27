from io import BytesIO

import qrcode
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse

from django_otp import login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice

from portal.utils.recovery_codes import (
    generate_plain_codes,
    replace_user_codes,
    verify_and_consume_code,
)
from portal.utils.security import issue_email_otp, verify_email_otp


@login_required
def mfa_setup(request):
    confirmed_device = (
        TOTPDevice.objects.filter(user=request.user, confirmed=True)
        .order_by("-id")
        .first()
    )
    if confirmed_device:
        return redirect("portal:dashboard")

    device = (
        TOTPDevice.objects.filter(user=request.user, confirmed=False)
        .order_by("-id")
        .first()
    )
    if device is None:
        device = TOTPDevice.objects.create(
            user=request.user, name="default", confirmed=False
        )

    if request.method == "POST":
        token = (request.POST.get("token") or "").strip()

        if not token:
            messages.error(
                request, "Enter the 6-digit code from your authenticator app."
            )
            return redirect("portal:mfa_setup")

        if device.verify_token(token):
            device.confirmed = True
            device.save(update_fields=["confirmed"])
            otp_login(request, device)

            messages.success(request, "Authenticator activated.")
            return redirect("portal:dashboard")

        messages.error(request, "Invalid code. Please try again.")
        return redirect("portal:mfa_setup")

    return render(
        request,
        "portal/mfa_setup.html",
        {"mode": "setup", "qr_url": reverse("portal:mfa_qr_png")},
    )


@login_required
def mfa_verify(request):
    profile = getattr(request.user, "profile", None)
    primary = getattr(profile, "primary_mfa_method", "totp")
    fallback_enabled = bool(getattr(profile, "email_fallback_enabled", True))

    has_totp = TOTPDevice.objects.filter(user=request.user, confirmed=True).exists()

    use = (request.GET.get("use") or "").strip().lower()
    method = primary

    if fallback_enabled:
        if use == "email":
            method = "email"
        elif use == "totp" and has_totp:
            method = "totp"

    # EMAIL OTP
    if method == "email":
        if request.method == "POST":
            action = (request.POST.get("action") or "").strip().lower()

            if action == "send":
                try:
                    issue_email_otp(request, request.user)
                    messages.success(
                        request, "We sent a verification code to your email."
                    )
                except Exception as e:
                    messages.error(request, str(e))
                return redirect(f"{reverse('portal:mfa_verify')}?use=email")

            code = (request.POST.get("code") or "").strip()
            if verify_email_otp(request, request.user, code):
                device = (
                    TOTPDevice.objects.filter(user=request.user, confirmed=True)
                    .order_by("-id")
                    .first()
                )
                if device is None:
                    device = TOTPDevice.objects.create(
                        user=request.user, name="email-session", confirmed=False
                    )

                otp_login(request, device)
                messages.success(request, "Verification successful.")
                return redirect("portal:dashboard")

            messages.error(request, "Invalid or expired code.")
            return redirect(f"{reverse('portal:mfa_verify')}?use=email")

        return render(
            request,
            "portal/mfa_verify.html",
            {
                "method": "email",
                "primary": primary,
                "fallback_enabled": fallback_enabled,
                "has_totp": has_totp,
            },
        )

    # TOTP
    device = (
        TOTPDevice.objects.filter(user=request.user, confirmed=True)
        .order_by("-id")
        .first()
        or TOTPDevice.objects.filter(user=request.user, confirmed=False)
        .order_by("-id")
        .first()
    )

    if not device:
        messages.error(request, "No authenticator is set up yet.")
        return redirect("portal:mfa_setup")

    if request.method == "POST":
        token = (request.POST.get("token") or "").strip()
        if device.verify_token(token):
            if not device.confirmed:
                device.confirmed = True
                device.save(update_fields=["confirmed"])

            otp_login(request, device)
            messages.success(request, "Authenticator verified.")
            return redirect("portal:dashboard")

        messages.error(request, "Invalid code. Please try again.")
        return redirect("portal:mfa_verify")

    return render(
        request,
        "portal/mfa_verify.html",
        {
            "method": "totp",
            "primary": primary,
            "fallback_enabled": fallback_enabled,
            "has_totp": has_totp,
        },
    )


@login_required
def mfa_qr_png(request):
    device = (
        TOTPDevice.objects.filter(user=request.user, confirmed=False)
        .order_by("-id")
        .first()
    )
    if device is None:
        device = TOTPDevice.objects.create(
            user=request.user, name="default", confirmed=False
        )

    uri = device.config_url
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return HttpResponse(buf.getvalue(), content_type="image/png")


@login_required
def mfa_recovery_codes(request):
    if request.method == "POST":
        codes = generate_plain_codes(10)
        replace_user_codes(request.user, codes)
        return render(request, "portal/mfa_recovery_codes.html", {"codes": codes})

    return render(request, "portal/mfa_recovery_codes.html", {"codes": None})


@login_required
def mfa_recovery(request):
    if request.method == "POST":
        code = (request.POST.get("code") or "").strip()
        if verify_and_consume_code(request.user, code):
            device = (
                TOTPDevice.objects.filter(user=request.user, confirmed=True)
                .order_by("-id")
                .first()
            )
            if device:
                otp_login(request, device)

            messages.success(request, "Recovery code accepted.")
            return redirect("portal:dashboard")

        messages.error(request, "Invalid or already-used recovery code.")
        return redirect("portal:mfa_recovery")

    return render(request, "portal/mfa_recovery.html")
