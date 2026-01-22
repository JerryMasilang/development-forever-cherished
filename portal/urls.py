from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from django.urls import reverse_lazy
from .forms import PortalPasswordResetForm
from .views import PortalLoginView
# SYNC TEST: urls.py multi-file push test

# SYNC TEST: urls.py multi-file push test


app_name = "portal"

urlpatterns = [
    path("mfa/setup/", views.mfa_setup, name="mfa_setup"),
    path("mfa/verify/", views.mfa_verify, name="mfa_verify"),
    path("", views.dashboard, name="dashboard"),
    path("dashboard/", views.dashboard, name="dashboard_page"),

    path("qr/", views.qr_control_center, name="qr_control_center"),
    path("qr/png/<str:qr_id>/", views.qr_png, name="qr_png"),
    path("mfa/qr.png", views.mfa_qr_png, name="mfa_qr_png"),
    path("logout/",auth_views.LogoutView.as_view(next_page=reverse_lazy("portal:login")),
    name="logout",),
    # path("login/",auth_views.LoginView.as_view(template_name="portal/login.html",
    #     redirect_authenticated_user=True),
    # name="login",),
    path("login/", PortalLoginView.as_view(), name="login"),
    path("users/", views.user_list, name="user_list"),
    path("users/create/", views.user_create, name="user_create"),
    path("users/<int:user_id>/edit/", views.user_edit, name="user_edit"),
    path("users/<int:user_id>/reset-mfa/", views.user_reset_mfa, name="user_reset_mfa"),
    path(
    "password-reset/",
    auth_views.PasswordResetView.as_view(
        template_name="portal/auth/password_reset.html",
        email_template_name="portal/auth/password_reset_email.html",
        subject_template_name="portal/auth/password_reset_subject.txt",
        success_url=reverse_lazy("portal:password_reset_done"),
    ),
    name="password_reset",
),



    path("password-reset/done/", auth_views.PasswordResetDoneView.as_view(
        template_name="portal/auth/password_reset_done.html"
    ), name="password_reset_done"),

    path(
    "reset/<uidb64>/<token>/",
    auth_views.PasswordResetConfirmView.as_view(
        template_name="portal/auth/password_reset_confirm.html",
        success_url=reverse_lazy("portal:password_reset_complete"),
    ),
    name="password_reset_confirm",
),


    path("reset/done/", auth_views.PasswordResetCompleteView.as_view(
        template_name="portal/auth/password_reset_complete.html"
    ), name="password_reset_complete"),
    path("apply/distributor/", views.distributor_apply, name="distributor_apply"),

]
