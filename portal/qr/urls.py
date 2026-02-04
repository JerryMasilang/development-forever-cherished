# portal/qr/urls.py
from django.urls import path
from . import views

app_name = "qr"

urlpatterns = [
    path("", views.qr_control_center, name="control_center"),
    path("png/<str:qr_id>/", views.qr_png, name="png"),
]
