# portal/urls.py
from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy
from portal.views_security import RateLimitedPasswordResetView
from . import views
from .forms import PortalPasswordResetForm
from portal import views_security


app_name = "portal"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("dashboard/", views.dashboard, name="dashboard_page"),

    # Auth
    path("login/", views.PortalLoginView.as_view(), name="login"),
    path(
        "logout/",
        auth_views.LogoutView.as_view(next_page=reverse_lazy("portal:login")),
        name="logout",
    ),

    # MFA (PRIMARY + VERIFY)
    path("mfa/setup/", views.mfa_setup, name="mfa_setup"),
    path("mfa/verify/", views.mfa_verify, name="mfa_verify"),
    path("mfa/qr.png", views.mfa_qr_png, name="mfa_qr_png"),

    # MFA Recovery (SECURITY MODULE ONLY)
    path("mfa/recovery/", views_security.mfa_recovery, name="mfa_recovery"),

    # QR
    path("qr/", views.qr_control_center, name="qr_control_center"),
    path("qr/png/<str:qr_id>/", views.qr_png, name="qr_png"),
    # User management
    path("users/", views.user_list, name="user_list"),
    path("users/create/", views.user_create, name="user_create"),
    path("users/<int:user_id>/edit/", views.user_edit, name="user_edit"),
    path("users/<int:user_id>/reset-mfa/", views.user_reset_mfa, name="user_reset_mfa"),
    path("users/<int:user_id>/reset-recovery/", views.user_reset_recovery, name="user_reset_recovery"),
    # Profile / Recovery Codes
    path("settings/", views_security.profile_settings, name="settings"),
    path("settings/recovery-codes/", views_security.recovery_codes_generate, name="recovery_codes_generate"),
    path("settings/verify/", views_security.stepup_verify, name="stepup_verify"),


    # Backward compatible (optional): keep old /profile/ route redirect to /settings/
    path("profile/", views_security.profile_settings, name="profile"),
    path("profile/recovery-codes/", views_security.recovery_codes_generate, name="recovery_codes_generate"),
        # Password reset
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

    # Distributor
    path("apply/distributor/", views.distributor_apply, name="distributor_apply"),
]