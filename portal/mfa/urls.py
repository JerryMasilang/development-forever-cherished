# portal/mfa/urls.py
from django.urls import path
from . import views
from portal import views_security

app_name = "mfa"

urlpatterns = [
    path("setup/", views.mfa_setup, name="mfa_setup"),
    path("verify/", views.mfa_verify, name="mfa_verify"),
    path("qr.png", views.mfa_qr_png, name="mfa_qr_png"),

    # IMPORTANT: recovery stays in views_security (approved)
    path("recovery/", views_security.mfa_recovery, name="mfa_recovery"),
]
