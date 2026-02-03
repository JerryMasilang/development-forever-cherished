# portal/users/urls.py
from django.urls import path
from . import views

app_name = "users"

urlpatterns = [
    path("", views.user_list, name="user_list"),
    path("create/", views.user_create, name="user_create"),
    path("<int:user_id>/edit/", views.user_edit, name="user_edit"),
    path("<int:user_id>/reset-mfa/", views.user_reset_mfa, name="user_reset_mfa"),
    path("<int:user_id>/reset-recovery/", views.user_reset_recovery, name="user_reset_recovery"),
]
