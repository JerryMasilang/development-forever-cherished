# portal/urls.py
from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy, include
from portal.audit.views import audit_log_view  # re-add ONLY if you use alias
from . import views
from .forms import PortalPasswordResetForm
from portal import views_security
from portal.views_security import RateLimitedPasswordResetView
from portal.mfa.views_security import mfa_recovery
from portal.distributor.views import distributor_apply  # import once
from . import views
from portal.profile.views import set_theme





app_name = "portal"

urlpatterns = [
    # -------------------------
    # Dashboard (FEATURE MODULE)
    # -------------------------
    path("", include(("portal.dashboard.urls", "dashboard"), namespace="dashboard")),

    # Legacy aliases (templates/old code may still use these)
    path("", views.dashboard, name="dashboard"),
    path("dashboard/", views.dashboard, name="dashboard_page"),

    # -------------------------
    # Auth (legacy aliases used by templates)
    # -------------------------
    path("login/", views.PortalLoginView.as_view(), name="login"),
    path("logout/", views.PortalLogoutView.as_view(), name="logout"),

    # Optional feature-style auth module routes
    path("auth/", include(("portal.auth.urls", "auth"), namespace="auth")),

    # -------------------------
    # Users (FEATURE MODULE)
    # -------------------------
    path("users/", include(("portal.users.urls", "users"), namespace="users")),

    # -------------------------
    # MFA (FEATURE MODULE)
    # -------------------------
    path("mfa/", include(("portal.mfa.urls", "mfa"), namespace="mfa")),

    # Legacy MFA aliases (keep old names working)
    path("mfa/setup/", views.mfa_setup, name="mfa_setup"),
    path("mfa/verify/", views.mfa_verify, name="mfa_verify"),
    path("mfa/qr.png", views.mfa_qr_png, name="mfa_qr_png"),
    # IMPORTANT: recovery stays in views_security (approved)
    # path("mfa/recovery/", views_security.mfa_recovery, name="mfa_recovery"),
    path("mfa/recovery/", mfa_recovery, name="mfa_recovery"),

    # -------------------------
    # Password Reset (SINGLE SET - rate-limited version)
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
    # QR (still legacy-routed here for now)
    # -------------------------
    # Legacy aliases (keep old reverse names working)
    path("qr/", include(("portal.qr.urls", "qr"), namespace="qr")),
    path("qr/", views.qr_control_center, name="qr_control_center"),
    path("qr/png/<str:qr_id>/", views.qr_png, name="qr_png"),


    # -------------------------
    # Profile / Settings
    # -------------------------
# -------------------------
# Profile / Settings
# -------------------------
    path("settings/", views_security.profile_settings, name="settings"),
    path("settings/recovery-codes/", views_security.recovery_codes_generate, name="recovery_codes_generate"),
    path("settings/verify/", views_security.stepup_verify, name="stepup_verify"),

    # Email change (querystring-based, approved flow)
    path("settings/email/verify/", views_security.email_change_verify, name="email_change_verify"),
    path("settings/email/confirm/", views_security.email_change_confirm, name="email_change_confirm"),

    # Audit feature module
    path("audit/", include(("portal.audit.urls", "audit"), namespace="audit")),

    # Distributor
    # path("apply/distributor/", views.distributor_apply, name="distributor_apply"),
    path("apply/", include(("portal.distributor.urls", "distributor"), namespace="distributor")),
    path("apply/distributor/", distributor_apply, name="distributor_apply"),
    path("settings/theme/", set_theme, name="set_theme"),

    # path("theme/", views.set_theme, name="set_theme"),

]
