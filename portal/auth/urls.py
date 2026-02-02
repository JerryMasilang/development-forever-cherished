from django.urls import path
from .views import (
    PortalLoginView,
    PortalLogoutView,
    PortalPasswordResetView,
    PortalPasswordResetDoneView,
    PortalPasswordResetConfirmView,
    PortalPasswordResetCompleteView,
)

app_name = "auth"

urlpatterns = [
    path("login/", PortalLoginView.as_view(), name="login"),
    path("logout/", PortalLogoutView.as_view(), name="logout"),

    path("password-reset/", PortalPasswordResetView.as_view(), name="password_reset"),
    path("password-reset/done/", PortalPasswordResetDoneView.as_view(), name="password_reset_done"),
    path(
        "password-reset/<uidb64>/<token>/",
        PortalPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "password-reset/complete/",
        PortalPasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
]
