from django.urls import path
from .views import home

app_name = "landing"

urlpatterns = [
    path("", home, name="home"),
]
