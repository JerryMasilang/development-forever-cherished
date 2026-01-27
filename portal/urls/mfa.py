from django.urls import path
from . import views


from django.contrib.auth import views
from django.urls import path,include, reverse_lazy
from portal import views_security



urlpatterns = [
    # We'll move your existing routes here next
    # MFA (PRIMARY + VERIFY)
    path("mfa/setup/", views.mfa_setup, name="mfa_setup"),
    path("mfa/verify/", views.mfa_verify, name="mfa_verify"),
    path("mfa/qr.png", views.mfa_qr_png, name="mfa_qr_png"),
    # MFA Recovery (SECURITY MODULE ONLY)
    path("mfa/recovery/", views_security.mfa_recovery, name="mfa_recovery"),
]

