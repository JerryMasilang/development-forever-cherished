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
from portal.utils.security import audit
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django_otp import login as otp_login
from portal.utils.security import audit




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
    