# portal/middleware/mfa.py
from __future__ import annotations

from django.shortcuts import redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin


class EnforceMFAMiddleware(MiddlewareMixin):
    ALLOWLIST_PREFIXES = (
        "/portal/login/",
        "/portal/logout/",
        "/portal/mfa/",
        "/portal/password-reset/",
        "/admin/",
        "/static/",
        "/media/",
    )

    SESSION_FLAG_KEYS = (
        "mfa_verified",
        "otp_verified",
        "mfa_ok",
        "mfa_verified_at",
    )

    def process_request(self, request):
        path = request.path or "/"

        for p in self.ALLOWLIST_PREFIXES:
            if path.startswith(p):
                return None

        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return None

        # django-otp support if installed
        try:
            if getattr(request.user, "is_verified", lambda: False)():
                return None
        except Exception:
            pass

        # session-based verification
        for k in self.SESSION_FLAG_KEYS:
            if request.session.get(k):
                return None

        return redirect("portal:mfa_verify")
