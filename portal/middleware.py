from django.shortcuts import redirect
from django.urls import reverse
from django_otp.plugins.otp_totp.models import TOTPDevice


class EnforceMFAMiddleware:
    """
    Forces authenticated users to complete OTP verification
    before accessing any portal pages.
    """

    EXEMPT_PATHS = (
    "/admin/",
    "/portal/mfa/",
    "/portal/login/",
    "/portal/logout/",
    "/portal/password-reset/",
    "/portal/reset/",
    "/static/",
    "/media/",
)


    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        # Allow exempt paths
        if any(path.startswith(p) for p in self.EXEMPT_PATHS):
            return self.get_response(request)

        user = request.user

        if user.is_authenticated:
            if not user.is_verified():
                # ✅ Option A: respect user's primary MFA method
                profile = getattr(user, "profile", None)
                primary = getattr(profile, "primary_mfa_method", "totp")

                # If primary is email, always go to the verify page (email UI)
                if primary == "email":
                    return redirect("portal:mfa_verify")

                # Otherwise primary is totp: go verify if device exists, else setup
                has_device = TOTPDevice.objects.filter(user=user, confirmed=True).exists()
                if has_device:
                    return redirect("portal:mfa_verify")
                return redirect("portal:mfa_setup")

        return self.get_response(request)
