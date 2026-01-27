from django.urls import path
from portal.views.qr import qr_control_center, qr_png

urlpatterns = [
    path("", qr_control_center, name="qr_control_center"),
    path("png/<str:qr_id>/", qr_png, name="qr_png"),
]
