from django.urls import path
from portal.views.dashboard import dashboard

urlpatterns = [
    path("", dashboard, name="dashboard"),
]
