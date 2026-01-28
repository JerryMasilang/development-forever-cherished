# portal/urls.py
from django.urls import path, include

app_name = "portal"

urlpatterns = [
    # Dashboard
    path("", include("portal.urls.dashboard")),

    # Auth (login/logout/password reset/apply)
    path("auth/", include("portal.urls.auth")),

    # MFA (setup/verify/recovery/recovery-codes)
    path("mfa/", include("portal.urls.mfa")),

    # Profile
    path("profile/", include("portal.urls.profile")),

    # QR
    path("qr/", include("portal.urls.qr")),

    # Users
    path("users/", include("portal.urls.users")),

    # Audit
    path("audit/", include("portal.urls.audit")),
]
