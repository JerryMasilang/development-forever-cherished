# from django.urls import path
# from . import views
# from . import views_security


# app_name = "profile"

# urlpatterns = [
# # Security/Profile (real implementations)
#   path("settings/", views_security.profile_settings, name="settings"),
#   path("settings/recovery-codes/", views_security.recovery_codes_generate, name="recovery_codes_generate"),
#   path("settings/verify/", views_security.stepup_verify, name="stepup_verify"),
#   path("settings/email/change/", views_security.request_email_change, name="request_email_change"),
#   path("settings/email/confirm/<uuid:token>/", views_security.confirm_email_change, name="confirm_email_change"),

#   path("email/change/verify/", views_security.email_change_verify, name="email_change_verify"),
#   path("email/change/confirm/", views_security.email_change_confirm, name="email_change_confirm"),

# ]

from django.urls import path
from . import views

app_name = "profile"

urlpatterns = [
    path("", views.profile_settings, name="profile"),
    path("recovery-codes/", views.profile_recovery_codes, name="profile_recovery_codes"),
    path("stepup/", views.profile_stepup_verify, name="profile_stepup_verify"),
    path("email-change/", views.profile_email_change, name="profile_email_change"),
    path("email-change/error/", views.profile_email_change_error, name="profile_email_change_error"),
]
