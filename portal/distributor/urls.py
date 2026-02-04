from django.urls import path
from . import views

app_name = "distributor"

urlpatterns = [
    path("distributor/", views.distributor_apply, name="apply"),
]
