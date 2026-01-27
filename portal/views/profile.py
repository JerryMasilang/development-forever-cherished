from __future__ import annotations
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.urls import reverse
from portal.forms.__init__ import EmailChangeForm
import uuid
from urllib.parse import quote, unquote
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.mail import send_mail
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django_otp.plugins.otp_totp.models import TOTPDevice
from portal.forms import ProfileSettingsForm, PortalPasswordChangeForm
from portal.utils.security import audit, step_up_is_verified


@login_required
def profile(request):
    active_tab = request.GET.get("tab", "general")
    email_form = EmailChangeForm(user=request.user)

    if request.method == "POST":
        action = request.POST.get("action", "")

        if action == "change_email":
            email_form = EmailChangeForm(request.POST, user=request.user)
            if email_form.is_valid():
                messages.success(
                    request, "Verification link sent to your new email address."
                )
                return redirect(f"{reverse('portal:profile')}?tab=security")

            active_tab = "security"
            messages.error(request, "Please correct the error below.")

    return render(
        request,
        "portal/profile.html",
        {"active_tab": active_tab, "email_form": email_form},
    )


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

        sessions.append(
            {
                "session_key": s.session_key,
                "is_current": (s.session_key == current_session_key),
                "expire_date": s.expire_date,
                "last_seen": data.get("last_seen", ""),
                "ip": data.get("ip", ""),
                "ua": data.get("ua", ""),
            }
        )

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

    # ✅ ALWAYS compute active_tab (default to profile)
    active_tab = (request.GET.get("tab") or "profile").strip().lower()

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()

        # =========================
        # Profile update
        # =========================
        if action == "profile":
            form = ProfileSettingsForm(
                request.POST, request.FILES, instance=profile, request_user=request.user
            )
            pwd_form = PortalPasswordChangeForm(request.user)

            if form.is_valid():
                form.save()
                audit(request, "PROFILE_UPDATED", target_user=request.user)
                messages.success(request, "Profile updated.")
                return redirect(str(reverse_lazy("portal:settings")) + "?tab=profile")

            # stay on profile tab on errors
            active_tab = "profile"

        # =========================
        # Change password (step-up gated)
        # =========================
        elif action == "password":
            form = ProfileSettingsForm(instance=profile, request_user=request.user)
            pwd_form = PortalPasswordChangeForm(request.user, request.POST)

            old_pwd = (request.POST.get("old_password") or "").strip()
            if not request.user.check_password(old_pwd):
                pwd_form.add_error("old_password", "Incorrect old password.")
                sessions = _get_user_sessions(request.user, request.session.session_key)
                return render(
                    request,
                    "portal/profile/settings.html",
                    {
                        "profile": profile,
                        "form": form,
                        "pwd_form": pwd_form,
                        "sessions": sessions,
                        "active_tab": "security",
                    },
                )

            if not pwd_form.is_valid():
                sessions = _get_user_sessions(request.user, request.session.session_key)
                return render(
                    request,
                    "portal/profile/settings.html",
                    {
                        "profile": profile,
                        "form": form,
                        "pwd_form": pwd_form,
                        "sessions": sessions,
                        "active_tab": "security",
                    },
                )

            # ✅ correct purpose for password is change_password
            if not step_up_is_verified(request, "change_password"):
                request.session["pending_password_change"] = True
                next_target = str(reverse_lazy("portal:settings")) + "?tab=security"
                verify_url = (
                    f"{reverse_lazy('portal:stepup_verify')}"
                    f"?purpose=change_password&next={quote(next_target, safe='')}"
                )
                return redirect(verify_url)

            pwd_form.save()
            audit(request, "PASSWORD_CHANGED", target_user=request.user)
            messages.success(request, "Password changed successfully.")
            request.session.pop("pending_password_change", None)
            return redirect(str(reverse_lazy("portal:settings")) + "?tab=security")

        # =========================
        # Session management
        # =========================
        elif action == "terminate_session":
            session_key = (request.POST.get("session_key") or "").strip()
            if session_key and session_key != request.session.session_key:
                _terminate_session(session_key)
                audit(request, "SESSION_TERMINATED", target_user=request.user)
                messages.success(request, "Session terminated.")
            return redirect(str(reverse_lazy("portal:settings")) + "?tab=security")

        elif action == "terminate_other_sessions":
            current = request.session.session_key
            for s in _get_user_sessions(request.user, current):
                if not s["is_current"]:
                    _terminate_session(s["session_key"])
            audit(request, "OTHER_SESSIONS_TERMINATED", target_user=request.user)
            messages.success(request, "Other sessions terminated.")
            return redirect(str(reverse_lazy("portal:settings")) + "?tab=security")

        # =========================
        # Email change (step-up -> verify new email)
        # =========================
        elif action == "email_change":
            form = ProfileSettingsForm(instance=profile, request_user=request.user)
            pwd_form = PortalPasswordChangeForm(request.user)

            new_email = (request.POST.get("new_email") or "").strip().lower()
            User = get_user_model()

            # Basic validation
            if not new_email or "@" not in new_email:
                return render(
                    request,
                    "portal/profile/settings.html",
                    {
                        "profile": profile,
                        "form": form,
                        "pwd_form": pwd_form,
                        "active_tab": "security",
                        "new_email": new_email,
                        "email_error": "Enter a valid email address.",
                        "sessions": _get_user_sessions(
                            request.user, request.session.session_key
                        ),
                    },
                )

            # Don't allow same email
            if request.user.email and new_email == request.user.email.lower():
                return render(
                    request,
                    "portal/profile/settings.html",
                    {
                        "profile": profile,
                        "form": form,
                        "pwd_form": pwd_form,
                        "active_tab": "security",
                        "new_email": new_email,
                        "email_error": "That is already your current email.",
                        "sessions": _get_user_sessions(
                            request.user, request.session.session_key
                        ),
                    },
                )

            # Prevent duplicate email across users
            if (
                User.objects.filter(email__iexact=new_email)
                .exclude(id=request.user.id)
                .exists()
            ):
                return render(
                    request,
                    "portal/profile/settings.html",
                    {
                        "profile": profile,
                        "form": form,
                        "pwd_form": pwd_form,
                        "active_tab": "security",
                        "new_email": new_email,
                        "email_error": "That email is already in use by another account.",
                        "sessions": _get_user_sessions(
                            request.user, request.session.session_key
                        ),
                    },
                )

            # Always overwrite pending email
            request.session["pending_new_email"] = new_email

            # ✅ FORCE step-up EVERY time for email change:
            # Clear any cached step-up markers for change_email in session
            for k in list(request.session.keys()):
                lk = k.lower()
                if "stepup" in lk and "change_email" in lk:
                    request.session.pop(k, None)

            # Require step-up
            if not step_up_is_verified(request, "change_email"):
                next_target = str(reverse_lazy("portal:email_change_verify"))
                verify_url = (
                    f"{reverse_lazy('portal:stepup_verify')}"
                    f"?purpose=change_email&next={quote(next_target, safe='')}"
                )
                return redirect(verify_url)

            return redirect("portal:email_change_verify")

        # =========================
        # Default fallthrough
        # =========================
        else:
            form = ProfileSettingsForm(instance=profile, request_user=request.user)
            pwd_form = PortalPasswordChangeForm(request.user)

    else:
        form = ProfileSettingsForm(instance=profile, request_user=request.user)
        pwd_form = PortalPasswordChangeForm(request.user)

    sessions = _get_user_sessions(request.user, request.session.session_key)
    email_msg = (request.GET.get("email_msg") or "").strip()

    return render(
        request,
        "portal/profile/settings.html",
        {
            "profile": profile,
            "form": form,
            "pwd_form": pwd_form,
            "sessions": sessions,
            "email_msg": email_msg,
            "active_tab": active_tab,  # ✅ ALWAYS pass it
        },
    )


@login_required
def stepup_verify(request):
    """
    Step-up verification page (Authenticator OR Email OTP).
    Reusable for sensitive actions (change_password, change_email, etc.)
    """
    purpose = (request.GET.get("purpose") or "general").strip()
    raw_next = request.GET.get("next") or str(reverse_lazy("portal:settings"))
    # ✅ decode %23 back into # (and any other encodings)
    next_url = unquote(raw_next)

    # ✅ validate using URL WITHOUT fragment
    next_url_for_check = next_url.split("#", 1)[0]
    if not url_has_allowed_host_and_scheme(
        next_url_for_check, allowed_hosts={request.get_host()}
    ):
        next_url = str(reverse_lazy("portal:settings"))

    method = (request.POST.get("method") or request.GET.get("method") or "").strip()

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
            return redirect(
                f"{reverse_lazy('portal:stepup_verify')}?purpose={purpose}&next={raw_next}"
            )

        if device.verify_token(code):
            step_up_mark_verified(request, purpose)
            audit(request, "STEPUP_TOTP_VERIFIED", target_user=request.user)
            messages.success(request, "Verified successfully.")
            return redirect(next_url)

        audit(request, "STEPUP_TOTP_FAILED", target_user=request.user)
        messages.error(request, "Invalid authenticator code.")
        return redirect(
            f"{reverse_lazy('portal:stepup_verify')}?purpose={purpose}&next={raw_next}"
        )

    # --- Email OTP send/verify ---
    from portal.utils.security import email_otp_issue, email_otp_verify, email_otp_clear

    if request.method == "POST" and method == "email_send":
        if not request.user.email:
            messages.error(request, "No email is set for your account.")
            return redirect(
                f"{reverse_lazy('portal:stepup_verify')}?purpose={purpose}&next={raw_next}"
            )

        code = email_otp_issue(request, purpose)

        subject = "Forever Cherished QR Portal verification code"
        body = (
            f"Your verification code is: {code}\n\n"
            f"This code expires in {getattr(settings, 'EMAIL_OTP_TTL_SECONDS', 300)//60} minutes.\n"
            f"If you did not request this, you can ignore this email."
        )
        send_mail(
            subject,
            body,
            settings.DEFAULT_FROM_EMAIL,
            [request.user.email],
            fail_silently=True,
        )

        audit(request, "STEPUP_EMAIL_OTP_SENT", target_user=request.user)
        messages.info(request, "We sent a verification code to your email.")
        return redirect(
            f"{reverse_lazy('portal:stepup_verify')}?purpose={purpose}&next={raw_next}&method=email_verify"
        )

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
        return redirect(
            f"{reverse_lazy('portal:stepup_verify')}?purpose={purpose}&next={raw_next}&method=email_verify"
        )

    return render(
        request,
        "portal/profile/stepup_verify.html",
        {
            "purpose": purpose,
            "next_url": next_url,  # decoded (safe for Cancel button)
            "method": method,
            "has_totp": TOTPDevice.objects.filter(
                user=request.user, confirmed=True
            ).exists(),
            "has_email": bool(request.user.email),
        },
    )


from django.core.signing import TimestampSigner, BadSignature, SignatureExpired


@login_required
def email_change_verify(request):
    new_email = (request.session.get("pending_new_email") or "").strip().lower()
    if not new_email:
        messages.error(request, "No pending email change request.")
        return redirect("portal:settings")

    profile = getattr(request.user, "profile", None)
    if profile is None:
        messages.error(request, "Profile not found.")
        return redirect("portal:settings")

    # ✅ Unique token id (single-use)
    jti = uuid.uuid4().hex
    profile.email_change_token_jti = jti
    profile.email_change_token_used_at = None
    profile.save(update_fields=["email_change_token_jti", "email_change_token_used_at"])

    signer = TimestampSigner()

    # token payload: "<jti>|<email>"
    token = signer.sign(f"{jti}|{new_email}")

    confirm_url = (
        request.build_absolute_uri(reverse_lazy("portal:email_change_confirm"))
        + f"?token={quote(token)}"
    )

    subject = "Confirm your new email - Forever Cherished QR Portal"
    body = (
        f"Confirm your new email by clicking this link:\n\n{confirm_url}\n\n"
        f"This link expires in 30 minutes."
    )

    send_mail(
        subject, body, settings.DEFAULT_FROM_EMAIL, [new_email], fail_silently=False
    )
    audit(request, "EMAIL_CHANGE_REQUESTED", target_user=request.user)

    msg = quote(f"We sent a confirmation link to {new_email}.")
    return redirect(
        str(reverse_lazy("portal:settings"))
        + f"?tab=security&scroll=top&email_msg={msg}"
    )


@login_required
def email_change_confirm(request):
    token = (request.GET.get("token") or "").strip()
    if not token:
        return render(
            request,
            "portal/profile/email_change_error.html",
            {
                "title": "Invalid link",
                "message": "This confirmation link is invalid. Please request a new email change.",
            },
            status=400,
        )

    signer = TimestampSigner()

    try:
        payload = signer.unsign(token, max_age=60 * 30)  # 30 minutes
        jti, new_email = payload.split("|", 1)
        new_email = new_email.strip().lower()
    except SignatureExpired:
        audit(request, "EMAIL_VERIFY_FAILED", target_user=request.user)
        return render(
            request,
            "portal/profile/email_change_error.html",
            {
                "title": "Link expired",
                "message": "This confirmation link has expired. Please request a new email change.",
            },
            status=400,
        )
    except (BadSignature, ValueError):
        audit(request, "EMAIL_VERIFY_FAILED", target_user=request.user)
        return render(
            request,
            "portal/profile/email_change_error.html",
            {
                "title": "Invalid link",
                "message": "This confirmation link is invalid. Please request a new email change.",
            },
            status=400,
        )

    profile = getattr(request.user, "profile", None)
    if profile is None:
        return render(
            request,
            "portal/profile/email_change_error.html",
            {
                "title": "Profile missing",
                "message": "We could not validate this request. Please request a new email change.",
            },
            status=400,
        )

    # ✅ Single-use enforcement
    if not profile.email_change_token_jti or profile.email_change_token_jti != jti:
        return render(
            request,
            "portal/profile/email_change_error.html",
            {
                "title": "Link already used",
                "message": "This confirmation link has already been used. Please request a new email change.",
            },
            status=400,
        )

    if profile.email_change_token_used_at is not None:
        return render(
            request,
            "portal/profile/email_change_error.html",
            {
                "title": "Link already used",
                "message": "This confirmation link has already been used. Please request a new email change.",
            },
            status=400,
        )

    # ✅ Duplicate check BEFORE saving
    User = get_user_model()
    if (
        User.objects.filter(email__iexact=new_email)
        .exclude(id=request.user.id)
        .exists()
    ):
        return render(
            request,
            "portal/profile/email_change_error.html",
            {
                "title": "Email already in use",
                "message": "That email is already in use by another account. Please request a new email change.",
            },
            status=400,
        )

    # ✅ Apply
    request.user.email = new_email
    request.user.save(update_fields=["email"])

    # ✅ Mark token used + clear session pending email
    profile.email_change_token_used_at = timezone.now()
    profile.email_change_token_jti = ""
    profile.save(update_fields=["email_change_token_used_at", "email_change_token_jti"])

    request.session.pop("pending_new_email", None)

    audit(request, "EMAIL_CHANGED", target_user=request.user)
    messages.success(request, "Email updated successfully.")
    return redirect("portal:settings")
