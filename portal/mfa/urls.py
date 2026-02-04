from django.urls import path
from . import views
from .views_security import mfa_recovery

app_name = "mfa"

urlpatterns = [
    path("setup/", views.mfa_setup, name="mfa_setup"),
    path("verify/", views.mfa_verify, name="mfa_verify"),
    path("recovery/", mfa_recovery, name="mfa_recovery"),
    path("qr.png", views.mfa_qr_png, name="mfa_qr_png"),
]
