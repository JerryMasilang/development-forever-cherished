# portal/urls.py
from django.contrib.auth import views as auth_views
from django.urls import path,include, reverse_lazy
from portal.views_security import RateLimitedPasswordResetView
from . import views
from .forms import PortalPasswordResetForm
from portal import views_security




from django.urls import path
app_name = "portal"
urlpatterns = [
    path("", include("portal.urls.dashboard")),
    path("auth/", include("portal.urls.auth")),
    path("mfa/", include("portal.urls.mfa")),
    path("qr/", include("portal.urls.qr")),
    path("users/", include("portal.urls.users")),
    path("audit/", include("portal.urls.audit")),
    path("profile/", include("portal.urls.profile")),
]
