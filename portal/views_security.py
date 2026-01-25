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
from django.contrib.sessions.models import Session
from django.utils import timezone




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
    


def _get_user_sessions(user, current_session_key: str | None):
    """
    Return list of sessions for this user (active, non-expired).
    """
    now = timezone.now()
    sessions = []

    for s in Session.objects.filter(expire_date__gte=now):
        data = s.get_decoded()
        if str(data.get("_auth_user_id")) != str(user.pk):
            continue

        sessions.append({
            "session_key": s.session_key,
            "is_current": (s.session_key == current_session_key),
            "expire_date": s.expire_date,
            "last_seen": data.get("last_seen", ""),
            "ip": data.get("ip", ""),
            "ua": data.get("ua", ""),
        })

    # Sort: current first, then by last_seen desc-ish
    def sort_key(x):
        return (0 if x["is_current"] else 1, x["last_seen"] or "")
    sessions.sort(key=sort_key)

    return sessions


def _terminate_session(session_key: str):
    Session.objects.filter(session_key=session_key).delete()


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

            old_pwd = (request.POST.get("old_password") or "").strip()
            if not request.user.check_password(old_pwd):
                pwd_form.add_error("old_password", "Incorrect old password.")
                sessions = _get_user_sessions(request.user, request.session.session_key)
                return render(request, "portal/profile/settings.html", {
                    "profile": profile,
                    "form": form,
                    "pwd_form": pwd_form,
                    "sessions": sessions,  # ✅ ADD THIS
                })

            if not pwd_form.is_valid():
                sessions = _get_user_sessions(request.user, request.session.session_key)
                return render(request, "portal/profile/settings.html", {
                    "profile": profile,
                    "form": form,
                    "pwd_form": pwd_form,
                    "sessions": sessions,  # ✅ ADD THIS
                })

            from portal.utils.security import step_up_is_verified
            if not step_up_is_verified(request, "change_password"):
                request.session["pending_password_change"] = True
                verify_url = (
                    f"{reverse_lazy('portal:stepup_verify')}"
                    f"?purpose=change_password&next={reverse_lazy('portal:settings')}%23tab-security"
                )
                return redirect(verify_url)

            pwd_form.save()
            audit(request, "PASSWORD_CHANGED", target_user=request.user)
            messages.success(request, "Password changed successfully.")
            request.session.pop("pending_password_change", None)
            return redirect("portal:settings")

        # ✅ ADD THIS BLOCK
        elif action == "terminate_session":
            session_key = request.POST.get("session_key") or ""
            if session_key and session_key != request.session.session_key:
                _terminate_session(session_key)
                audit(request, "SESSION_TERMINATED", target_user=request.user)
                messages.success(request, "Session terminated.")
            return redirect(reverse_lazy("portal:settings") + "#tab-security")

        # ✅ ADD THIS BLOCK
        elif action == "terminate_other_sessions":
            current = request.session.session_key
            for s in _get_user_sessions(request.user, current):
                if not s["is_current"]:
                    _terminate_session(s["session_key"])
            audit(request, "OTHER_SESSIONS_TERMINATED", target_user=request.user)
            messages.success(request, "Other sessions terminated.")
            return redirect(reverse_lazy("portal:settings") + "#tab-security")

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

    # ✅ ALSO ADD sessions HERE
    sessions = _get_user_sessions(request.user, request.session.session_key)
    return render(request, "portal/profile/settings.html", {
        "profile": profile,
        "form": form,
        "pwd_form": pwd_form,
        "sessions": sessions,
    })


@login_required
def request_email_change(request):
    profile = request.user.profile

    if request.method == "POST":
        form = EmailChangeForm(request.POST)

        if not form.is_valid():
            return render(request, "portal/profile/email_change.html", {"form": form})

        # Require step-up
        if not step_up_is_verified(request, "change_email"):
            verify_url = (
                f"{reverse_lazy('portal:stepup_verify')}"
                f"?purpose=change_email&next={reverse_lazy('portal:request_email_change')}"
            )
            request.session["pending_email_change"] = form.cleaned_data["new_email"]
            return redirect(verify_url)

        # Step-up passed → create token
        new_email = form.cleaned_data["new_email"]
        token = uuid.uuid4()

        profile.pending_email = new_email
        profile.email_change_token = token
        profile.email_change_requested_at = timezone.now()
        profile.save()

        confirm_url = request.build_absolute_uri(
            reverse_lazy("portal:confirm_email_change", args=[str(token)])
        )

        send_mail(
            "Confirm your new email",
            f"Click to confirm your new email:\n\n{confirm_url}",
            settings.DEFAULT_FROM_EMAIL,
            [new_email],
            fail_silently=False,
        )

        audit(request, "EMAIL_CHANGE_REQUESTED", target_user=request.user)
        messages.info(request, "Verification email sent to the new address.")
        return redirect("portal:settings")

    else:
        form = EmailChangeForm()

    return render(request, "portal/profile/email_change.html", {"form": form})



@login_required
def confirm_email_change(request, token):
    profile = request.user.profile

    if not profile.email_change_token or str(profile.email_change_token) != token:
        messages.error(request, "Invalid or expired email change link.")
        return redirect("portal:settings")

    request.user.email = profile.pending_email
    request.user.save()

    profile.pending_email = None
    profile.email_change_token = None
    profile.email_change_requested_at = None
    profile.save()

    audit(request, "EMAIL_CHANGED", target_user=request.user)
    messages.success(request, "Your email address has been updated.")
    return redirect("portal:settings")



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

