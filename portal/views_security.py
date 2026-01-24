# portal/views_security.py
from __future__ import annotations
from django.contrib.auth.views import PasswordResetView
from django.urls import reverse_lazy
from portal.utils.security import rate_limit_hit, get_client_ip, audit
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.http import HttpResponseRedirect
from django_otp import login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice
from .forms import ProfileSettingsForm, PortalPasswordChangeForm
from portal.utils.security import audit
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import url_has_allowed_host_and_scheme



from portal.utils.security import (
    audit,
    generate_recovery_codes,
    replace_recovery_codes,
    verify_and_consume_recovery_code,
)


@login_required
def mfa_recovery(request):
    """
    Use a recovery code instead of TOTP.
    """
    if request.method == "POST":
        code = (request.POST.get("code") or "").strip()
        if verify_and_consume_recovery_code(request.user, code):
            # Satisfy OTP by attaching a confirmed device if it exists
            device = TOTPDevice.objects.filter(user=request.user, confirmed=True).order_by("-id").first()
            if device:
                otp_login(request, device)

            audit(request, "MFA_RECOVERY_CODE_USED", target_user=request.user)
            messages.success(request, "Recovery code accepted.")
            return redirect("portal:dashboard")

        messages.error(request, "Invalid or already-used recovery code.")
        return redirect("portal:mfa_recovery")

    return render(request, "portal/mfa_recovery.html")


@login_required
def recovery_codes_generate(request):
    """
    Generate recovery codes (show plaintext ONCE).
    Put this in Profile/Settings (not on MFA page).
    """
    if request.method == "POST":
        codes = generate_recovery_codes(10)
        replace_recovery_codes(request.user, codes)
        audit(request, "RECOVERY_CODES_GENERATED", target_user=request.user)
        return render(request, "portal/profile/recovery_codes.html", {"codes": codes})

    return render(request, "portal/profile/recovery_codes.html", {"codes": None})


class RateLimitedPasswordResetView(PasswordResetView):
    """
    Password reset with rate limiting:
    - 5 attempts per email per hour
    - 10 attempts per IP per hour
    """

    success_url = reverse_lazy("portal:password_reset_done")

    # 🔒 RATE LIMIT CONSTANTS (MUST exist on the class)
    LIMIT_EMAIL = 5
    LIMIT_IP = 10
    WINDOW_SECONDS = 60 * 60  # 1 hour

    def form_valid(self, form):
        ip = get_client_ip(self.request) or "unknown"
        email = (form.cleaned_data.get("email") or "").strip().lower()

        ip_key = f"pwreset:ip:{ip}"
        email_key = f"pwreset:email:{email}" if email else "pwreset:email:unknown"

        blocked = (
            rate_limit_hit(ip_key, self.LIMIT_IP, self.WINDOW_SECONDS)
            or rate_limit_hit(email_key, self.LIMIT_EMAIL, self.WINDOW_SECONDS)
        )

        # 🚫 BLOCK: do NOT send email
        if blocked:
            audit(self.request, "PWRESET_RATE_LIMIT_BLOCKED")
            return HttpResponseRedirect(self.get_success_url())

        # ✅ ALLOW: normal Django behavior (sends email)
        return super().form_valid(form)
    

@login_required
def profile_settings(request):
    profile = getattr(request.user, "profile", None)

    if request.method == "POST":
        action = request.POST.get("action") or ""

        if action == "profile":
            form = ProfileSettingsForm(
                request.POST,
                request.FILES,
                instance=profile,
                request_user=request.user
            )
            if form.is_valid():
                form.save()
                audit(request, "PROFILE_UPDATED", target_user=request.user)
                messages.success(request, "Profile updated.")
                return redirect("portal:settings")
            pwd_form = PortalPasswordChangeForm(request.user)

        elif action == "password":
            form = ProfileSettingsForm(instance=profile, request_user=request.user)
            pwd_form = PortalPasswordChangeForm(request.user, request.POST)

            # 1) Old password must be correct first (inline error)
            old_pwd = (request.POST.get("old_password") or "").strip()
            if not request.user.check_password(old_pwd):
                pwd_form.add_error("old_password", "Incorrect old password.")
                return render(request, "portal/profile/settings.html", {
                    "profile": profile,
                    "form": form,
                    "pwd_form": pwd_form,
                    "active_tab": "security",
                })

            # 2) Validate new passwords before step-up
            if not pwd_form.is_valid():
                return render(request, "portal/profile/settings.html", {
                    "profile": profile,
                    "form": form,
                    "pwd_form": pwd_form,
                    "active_tab": "security",
                })

            # 3) If form is valid, THEN require step-up
            from portal.utils.security import step_up_is_verified
            if not step_up_is_verified(request, "change_password"):
                request.session["pending_password_change"] = True  # marker
                verify_url = (
                    f"{reverse_lazy('portal:stepup_verify')}"
                    f"?purpose=change_password&next={reverse_lazy('portal:settings')}%23tab-security"
                )
                return redirect(verify_url)

            # 4) Step-up already satisfied -> save
            pwd_form.save()
            audit(request, "PASSWORD_CHANGED", target_user=request.user)
            messages.success(request, "Password changed successfully.")
            request.session.pop("pending_password_change", None)
            return redirect("portal:settings")

        else:
            form = ProfileSettingsForm(
                instance=profile,
                request_user=request.user
            )
            pwd_form = PortalPasswordChangeForm(request.user)

    else:
        form = ProfileSettingsForm(
            instance=profile,
            request_user=request.user
        )
        pwd_form = PortalPasswordChangeForm(request.user)

    return render(request, "portal/profile/settings.html", {
        "profile": profile,
        "form": form,
        "pwd_form": pwd_form,
    })



@login_required
def stepup_verify(request):
    """
    Step-up verification page (Authenticator OR Email OTP).
    Reusable for sensitive actions (change_password, change_email, download_pdf, etc.)
    """
    purpose = (request.GET.get("purpose") or "general").strip()
    next_url = request.GET.get("next") or reverse_lazy("portal:settings")

    # Safety: prevent open redirect
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        next_url = reverse_lazy("portal:settings")

    method = (request.POST.get("method") or request.GET.get("method") or "").strip()

    # If already verified, just go back
    from portal.utils.security import step_up_is_verified, step_up_mark_verified
    if step_up_is_verified(request, purpose):
        return redirect(next_url)

    # --- TOTP verify ---
    if request.method == "POST" and method == "totp":
        code = (request.POST.get("code") or "").strip()

        device = (
            TOTPDevice.objects.filter(user=request.user, confirmed=True)
            .order_by("-id")
            .first()
        )
        if not device:
            messages.error(request, "No authenticator is configured for your account.")
            return redirect(f"{reverse_lazy('portal:stepup_verify')}?purpose={purpose}&next={next_url}")

        if device.verify_token(code):
            step_up_mark_verified(request, purpose)
            audit(request, "STEPUP_TOTP_VERIFIED", target_user=request.user)

            messages.success(request, "Verified successfully.")
            return redirect(next_url)

        audit(request, "STEPUP_TOTP_FAILED", target_user=request.user)
        messages.error(request, "Invalid authenticator code.")
        return redirect(f"{reverse_lazy('portal:stepup_verify')}?purpose={purpose}&next={next_url}")

    # --- Email OTP send ---
    from portal.utils.security import email_otp_issue, email_otp_verify, email_otp_clear

    if request.method == "POST" and method == "email_send":
        if not request.user.email:
            messages.error(request, "No email is set for your account.")
            return redirect(f"{reverse_lazy('portal:stepup_verify')}?purpose={purpose}&next={next_url}")

        code = email_otp_issue(request, purpose)

        subject = "Forever Cherished QR Portal verification code"
        body = (
            f"Your verification code is: {code}\n\n"
            f"This code expires in {getattr(settings, 'EMAIL_OTP_TTL_SECONDS', 300)//60} minutes.\n"
            f"If you did not request this, you can ignore this email."
        )
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [request.user.email], fail_silently=True)

        audit(request, "STEPUP_EMAIL_OTP_SENT", target_user=request.user)
        messages.info(request, "We sent a verification code to your email.")
        return redirect(f"{reverse_lazy('portal:stepup_verify')}?purpose={purpose}&next={next_url}&method=email_verify")

    # --- Email OTP verify ---
    if request.method == "POST" and method == "email_verify":
        code = (request.POST.get("code") or "").strip()
        if email_otp_verify(request, purpose, code):
            email_otp_clear(request, purpose)
            step_up_mark_verified(request, purpose)
            audit(request, "STEPUP_EMAIL_VERIFIED", target_user=request.user)
            messages.success(request, "Verified successfully.")
            return redirect(next_url)

        audit(request, "STEPUP_EMAIL_FAILED", target_user=request.user)
        messages.error(request, "Invalid or expired email code.")
        return redirect(f"{reverse_lazy('portal:stepup_verify')}?purpose={purpose}&next={next_url}&method=email_verify")

    return render(
        request,
        "portal/profile/stepup_verify.html",
        {
            "purpose": purpose,
            "next_url": next_url,
            "method": method,
            "has_totp": TOTPDevice.objects.filter(user=request.user, confirmed=True).exists(),
            "has_email": bool(request.user.email),
        },
    )

