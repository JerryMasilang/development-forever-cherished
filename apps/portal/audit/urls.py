from django.urls import path
from portal import views  # TEMP: still using old views.py


from django.contrib.auth import views as auth_views
from django.urls import path, include, reverse_lazy
from portal.views_security import RateLimitedPasswordResetView
from . import views
from .forms import PortalPasswordResetForm
from portal import views_security
from portal.views.audit import audit_log_view

urlpatterns = [
    # We'll move your existing routes here next
]
