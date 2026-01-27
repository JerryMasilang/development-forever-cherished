from django.urls import path
from portal.views.auth import PortalLoginView, distributor_apply
from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy
from portal.views.auth import RateLimitedPasswordResetView


urlpatterns = [
    path("login/", PortalLoginView.as_view(), name="login"),
    path(
        "logout/",
        auth_views.LogoutView.as_view(next_page=reverse_lazy("portal:login")),
        name="logout",
    ),
    path("distributor/apply/", distributor_apply, name="distributor_apply"),
]
