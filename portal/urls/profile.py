from django.urls import path

# from portal import views  # TEMP: still using old views.py
from . import views
from portal import views_security
from portal.views.profile import (
    profile_settings,
    stepup_verify,
    email_change_verify,
    email_change_confirm,
)


urlpatterns = [
    # We'll move your existing routes here next
    # Profile / Recovery Codes
    path("settings/", views_security.profile_settings, name="settings"),
    path(
        "settings/recovery-codes/",
        views_security.recovery_codes_generate,
        name="recovery_codes_generate",
    ),
    path("settings/verify/", views_security.stepup_verify, name="stepup_verify"),
    path(
        "settings/email/change/",
        views_security.request_email_change,
        name="request_email_change",
    ),
    path(
        "settings/email/confirm/<uuid:token>/",
        views_security.confirm_email_change,
        name="confirm_email_change",
    ),
    path("profile/", views_security.profile_settings, name="profile"),
    path(
        "profile/recovery-codes/",
        views_security.recovery_codes_generate,
        name="recovery_codes_generate",
    ),
    path(
        "email/change/verify/",
        views_security.email_change_verify,
        name="email_change_verify",
    ),
    path(
        "email/change/confirm/",
        views_security.email_change_confirm,
        name="email_change_confirm",
    ),
]
