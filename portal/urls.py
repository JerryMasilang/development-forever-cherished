# portal/urls.py
from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy, include

from . import views
from .forms import PortalPasswordResetForm
from portal import views_security
from portal.views_security import RateLimitedPasswordResetView

app_name = "portal"

urlpatterns = [
    # -------------------------
    # Auth (legacy aliases used by templates)
    # -------------------------
    path("login/", views.PortalLoginView.as_view(), name="login"),
    path("logout/", views.PortalLogoutView.as_view(), name="logout"),

    # Optional feature-style auth module routes (kept)
    path("auth/", include(("portal.auth.urls", "auth"), namespace="auth")),
    # path("", include(("portal.dashboard.urls", "dashboard"))),
    path("", include(("portal.dashboard.urls", "dashboard"), namespace="dashboard")),



    # -------------------------
    # Password Reset (KEEP ONLY ONE SET)
    # NOTE: Keeping the RateLimitedPasswordResetView as the single active one.
    # This matches your security direction without breaking templates.
    # -------------------------
    path(
        "password-reset/",
        RateLimitedPasswordResetView.as_view(
            template_name="portal/auth/password_reset.html",
            email_template_name="portal/auth/password_reset_email.html",
            subject_template_name="portal/auth/password_reset_subject.txt",
            success_url=reverse_lazy("portal:password_reset_done"),
            form_class=PortalPasswordResetForm,
        ),
        name="password_reset",
    ),
    path(
        "password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="portal/auth/password_reset_done.html",
        ),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="portal/auth/password_reset_confirm.html",
            success_url=reverse_lazy("portal:password_reset_complete"),
        ),
        name="password_reset_confirm",
    ),
    path(
        "reset/done/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="portal/auth/password_reset_complete.html",
        ),
        name="password_reset_complete",
    ),

    # -------------------------
    # MFA (legacy routes used by templates)
    # -------------------------
    path("mfa/setup/", views.mfa_setup, name="mfa_setup"),
    path("mfa/verify/", views.mfa_verify, name="mfa_verify"),
    path("mfa/qr.png", views.mfa_qr_png, name="mfa_qr_png"),

    # IMPORTANT: keep SECURITY version for recovery (as you instructed)
    path("mfa/recovery/", views_security.mfa_recovery, name="mfa_recovery"),

    # -------------------------
    # QR
    # -------------------------
    path("qr/", views.qr_control_center, name="qr_control_center"),
    path("qr/png/<str:qr_id>/", views.qr_png, name="qr_png"),

    # -------------------------
    # Users (user management)
    # -------------------------
    path("users/", views.user_list, name="user_list"),
    path("users/create/", views.user_create, name="user_create"),
    path("users/<int:user_id>/edit/", views.user_edit, name="user_edit"),
    path("users/<int:user_id>/reset-mfa/", views.user_reset_mfa, name="user_reset_mfa"),
    path("users/<int:user_id>/reset-recovery/", views.user_reset_recovery, name="user_reset_recovery"),

    # -------------------------
    # Profile / Settings (security + profile module)
    # -------------------------
    path("settings/", views_security.profile_settings, name="settings"),
    path("settings/recovery-codes/", views_security.recovery_codes_generate, name="recovery_codes_generate"),
    path("settings/verify/", views_security.stepup_verify, name="stepup_verify"),

    path("settings/email/change/", views_security.request_email_change, name="request_email_change"),
    path("settings/email/confirm/<uuid:token>/", views_security.confirm_email_change, name="confirm_email_change"),

    # Legacy alias (if templates still reference portal:profile)
    path("profile/", views.profile_settings, name="profile"),

    # Feature-style profile module URLs (if used elsewhere)
    path("profile/", include(("portal.profile.urls", "profile"), namespace="profile")),

    # -------------------------
    # Audit + email change flow pages
    # -------------------------
    path("audit/", views_security.audit_log_view, name="audit_log"),
    path("email/change/verify/", views_security.email_change_verify, name="email_change_verify"),
    path("email/change/confirm/", views_security.email_change_confirm, name="email_change_confirm"),

    # -------------------------
    # Distributor
    # -------------------------
    path("apply/distributor/", views.distributor_apply, name="distributor_apply"),
]
