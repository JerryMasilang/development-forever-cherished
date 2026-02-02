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
