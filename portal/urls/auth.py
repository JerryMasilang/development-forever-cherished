# portal/urls/auth.py
from django.urls import path
from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy

from portal.views.auth import PortalLoginView, distributor_apply, RateLimitedPasswordResetView

urlpatterns = [
    # Canonical auth endpoints
    path("login/", PortalLoginView.as_view(), name="login"),
    path(
        "logout/",
        auth_views.LogoutView.as_view(next_page=reverse_lazy("portal:login")),
        name="logout",
    ),

    # Distributor application
    path("distributor/apply/", distributor_apply, name="distributor_apply"),

    # Password reset (canonical, NOT /registration/)
    path(
        "password-reset/",
        RateLimitedPasswordResetView.as_view(
            template_name="portal/auth/password_reset.html",
            email_template_name="portal/auth/password_reset_email.html",
            subject_template_name="portal/auth/password_reset_subject.txt",
            success_url=reverse_lazy("portal:password_reset_done"),
        ),
        name="password_reset",
    ),
    path(
        "password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="portal/auth/password_reset_done.html"
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
            template_name="portal/auth/password_reset_complete.html"
        ),
        name="password_reset_complete",
    ),
]
