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
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from urllib.parse import quote
from portal.utils.security import step_up_is_verified
from portal.forms import EmailChangeForm
import uuid
from django.contrib.auth import get_user_model
from portal.utils.security import step_up_is_verified
from urllib.parse import unquote
from portal.audit.views import audit_log_view

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import redirect, render
from django.utils import timezone
from django_otp import login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice

from portal.utils.security import audit, verify_and_consume_recovery_code



# ---- Profile Security (moved to feature module) ----
from portal.profile.views_security import (
    profile_settings,
    stepup_verify,
    request_email_change,
    confirm_email_change,
    email_change_verify,
    email_change_confirm,
)






@login_required
def mfa_recovery(request):
    if request.method == "POST":
        code = (request.POST.get("code") or "").strip()
        if verify_and_consume_recovery_code(request.user, code):
            device = (
                TOTPDevice.objects.filter(user=request.user, confirmed=True)
                .order_by("-id")
                .first()
            )
            if device:
                otp_login(request, device)

            audit(request, "MFA_RECOVERY_CODE_USED", target_user=request.user)
            messages.success(request, "Recovery code accepted.")
            return redirect("portal:dashboard:dashboard")

        messages.error(request, "Invalid or already-used recovery code.")
        return redirect("portal:mfa:mfa_recovery")

    return render(request, "portal/mfa_recovery.html")


from portal.utils.security import (
    audit,
    generate_recovery_codes,
    replace_recovery_codes,
    verify_and_consume_recovery_code,
)



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
    
