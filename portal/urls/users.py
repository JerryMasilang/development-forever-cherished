from django.urls import path
from portal.views.users import (
    user_list,
    user_create,
    user_edit,
    user_reset_mfa,
    user_reset_recovery,
)

urlpatterns = [
    path("", user_list, name="user_list"),
    path("create/", user_create, name="user_create"),
    path("<int:user_id>/edit/", user_edit, name="user_edit"),
    path("<int:user_id>/reset-mfa/", user_reset_mfa, name="user_reset_mfa"),
    path(
        "<int:user_id>/reset-recovery/", user_reset_recovery, name="user_reset_recovery"
    ),
]
