# portal/middleware.py
from django.shortcuts import redirect
from django.urls import reverse


class PortalMfaGateMiddleware:
    """
    If user is logged in but not MFA-verified, redirect to MFA verify.
    Supports both:
    - django-otp verified sessions (TOTP)
    - Email OTP verified sessions (session flag)
    """

    SESSION_MFA_VERIFIED = "portal_mfa_verified"

    ALLOW_PATH_PREFIXES = (
        "/portal/login/",
        "/portal/logout/",
        "/portal/mfa/setup/",
        "/portal/mfa/verify/",
        "/portal/mfa/recovery/",
        "/portal/mfa/qr.png",
        "/portal/password-reset/",
        "/portal/reset/",
        "/portal/auth/",  # keep auth module safe
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only gate portal pages
        if not request.path.startswith("/portal/"):
            return self.get_response(request)

        # Always allow these paths (avoid loops)
        for p in self.ALLOW_PATH_PREFIXES:
            if request.path.startswith(p):
                return self.get_response(request)

        # If not logged in, allow normal flow
        if not request.user.is_authenticated:
            return self.get_response(request)

        # ✅ Verified by django-otp?
        is_verified = getattr(request.user, "is_verified", None)
        if callable(is_verified) and request.user.is_verified():
            return self.get_response(request)

        # ✅ Verified by EMAIL OTP session flag?
        if request.session.get(self.SESSION_MFA_VERIFIED):
            return self.get_response(request)

        # Otherwise force MFA verify
        return redirect(reverse("portal:mfa_verify"))
