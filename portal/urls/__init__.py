# from django.urls import include, path

# app_name = "portal"

# urlpatterns = [
#     path("", include("portal.urls.dashboard")),
#     path("auth/", include("portal.urls.auth")),
#     path("mfa/", include("portal.urls.mfa")),
#     path("qr/", include("portal.urls.qr")),
#     path("users/", include("portal.urls.users")),
#     path("audit/", include("portal.urls.audit")),
#     path("profile/", include("portal.urls.profile")),
# ]

from django.urls import path, include

urlpatterns = [
    path("", include("portal.urls.dashboard")),
    path("auth/", include("portal.urls.auth")),
    path("mfa/", include("portal.urls.mfa")),
    path("users/", include("portal.urls.users")),
]
