from django.urls import path
from . import views
from portal import views  # TEMP: still using old views.py



from django.contrib.auth import views as auth_views



urlpatterns = [
    # We'll move your existing routes here next
        # QR
    path("qr/", views.qr_control_center, name="qr_control_center"),
    path("qr/png/<str:qr_id>/", views.qr_png, name="qr_png"),
 
]
