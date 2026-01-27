from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    # We'll move your existing routes here next
    # User management
    path("users/", views.user_list, name="user_list"),
    path("users/create/", views.user_create, name="user_create"),
    path("users/<int:user_id>/edit/", views.user_edit, name="user_edit"),
    path("users/<int:user_id>/reset-mfa/", views.user_reset_mfa, name="user_reset_mfa"),
    path("users/<int:user_id>/reset-recovery/", views.user_reset_recovery, name="user_reset_recovery"),

]
