# portal/middleware/mfa.py
from __future__ import annotations

from django.shortcuts import redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin


class EnforceMFAMiddleware(MiddlewareMixin):
    """
    Enforce MFA (django-otp) for authenticated users.

    - If user is authenticated and NOT otp_verified, redirect to MFA verify page.
    - Bypass admin, auth, password reset, MFA setup/verify endpoints, and static/media.
    """

    def _is_bypassed(self, request) -> bool:
        path = request.path or "/"

        # Always allow static/media (especially in DEBUG)
        if path.startswith("/static/") or path.startswith("/media/"):
            return True

        # Allow Django admin (prevents admin redirect loop)
        if path.startswith("/admin/"):
            return True

        # Allow all portal auth endpoints (login/logout/password reset/apply)
        if path.startswith("/portal/auth/"):
            return True

        # Allow MFA endpoints themselves (prevents infinite loop)
        if path.startswith("/portal/mfa/"):
            return True

        return False

    def process_request(self, request):
        # If bypassed, do nothing
        if self._is_bypassed(request):
            return None

        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return None

        # django-otp attaches `is_verified()` to the user when OTPMiddleware runs
        is_verified = getattr(user, "is_verified", None)
        if callable(is_verified) and user.is_verified():
            return None

        # If OTPMiddleware isn't loaded for some reason, be safe and don't enforce
        if not callable(is_verified):
            return None

        # Enforce MFA: redirect to verify page
        verify_url = reverse("portal:mfa_verify")
        return redirect(verify_url)
