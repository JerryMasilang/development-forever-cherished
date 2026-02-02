# portal/urls.py
from django.urls import path, reverse_lazy, include

from portal.views_security import RateLimitedPasswordResetView
from portal import views_security

from . import views
from .forms import PortalPasswordResetForm

app_name = "portal"

urlpatterns = [
    # Dashboard
    path("", views.dashboard, name="dashboard"),
    path("dashboard/", views.dashboard, name="dashboard_page"),

    # Auth (legacy names used by templates)
    path("login/", views.PortalLoginView.as_view(), name="login"),
    path("logout/", views.PortalLogoutView.as_view(), name="logout"),

    # Password reset (SINGLE source of truth: rate-limited)
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
        views.PortalPasswordResetDoneView.as_view(),
        name="password_reset_done",
    ),
    path(
        "password-reset/<uidb64>/<token>/",
        views.PortalPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "password-reset/complete/",
        views.PortalPasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),

    # Optional: keep auth module URLs available under /portal/auth/
    # (Does NOT conflict because the paths are different: /portal/auth/login/ etc.)
    path("auth/", include(("portal.auth.urls", "auth"), namespace="auth")),

    # MFA (single set)
    path("mfa/setup/", views.mfa_setup, name="mfa_setup"),
    path("mfa/verify/", views.mfa_verify, name="mfa_verify"),
    path("mfa/recovery/", views_security.mfa_recovery, name="mfa_recovery"),
    path("mfa/qr.png", views.mfa_qr_png, name="mfa_qr_png"),

    # QR
    path("qr/", views.qr_control_center, name="qr_control_center"),
    path("qr/png/<str:qr_id>/", views.qr_png, name="qr_png"),

    # User management
    path("users/", views.user_list, name="user_list"),
    path("users/create/", views.user_create, name="user_create"),
    path("users/<int:user_id>/edit/", views.user_edit, name="user_edit"),
    path("users/<int:user_id>/reset-mfa/", views.user_reset_mfa, name="user_reset_mfa"),
    path("users/<int:user_id>/reset-recovery/", views.user_reset_recovery, name="user_reset_recovery"),

    # Profile / Settings
    path("settings/", views_security.profile_settings, name="settings"),
    path("settings/recovery-codes/", views_security.recovery_codes_generate, name="recovery_codes_generate"),
    path("settings/verify/", views_security.stepup_verify, name="stepup_verify"),

    # Email change (newer flow)
    path("email/change/verify/", views_security.email_change_verify, name="email_change_verify"),
    path("email/change/confirm/", views_security.email_change_confirm, name="email_change_confirm"),

    # Legacy profile alias + profile module (kept)
    path("profile/", views.profile_settings, name="profile"),
    path("profile/", include(("portal.profile.urls", "profile"), namespace="profile")),

    # Distributor
    path("apply/distributor/", views.distributor_apply, name="distributor_apply"),

    # Audit
    path("audit/", views_security.audit_log_view, name="audit_log"),
]
