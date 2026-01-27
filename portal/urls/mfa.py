

from django.urls import path
from portal.views.mfa import mfa_setup, mfa_verify, mfa_qr_png, mfa_recovery, mfa_recovery_codes

urlpatterns = [
    path("setup/", mfa_setup, name="mfa_setup"),
    path("verify/", mfa_verify, name="mfa_verify"),
    path("qr.png", mfa_qr_png, name="mfa_qr_png"),
    path("recovery/", mfa_recovery, name="mfa_recovery"),
    path("recovery-codes/", mfa_recovery_codes, name="mfa_recovery_codes"),
]
