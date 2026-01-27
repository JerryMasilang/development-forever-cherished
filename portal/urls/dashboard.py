from django.urls import path
from . import views

urlpatterns = [
    # We'll move your existing routes here next
    path("", views.dashboard, name="dashboard"),
    path("dashboard/", views.dashboard, name="dashboard_page"),
]
