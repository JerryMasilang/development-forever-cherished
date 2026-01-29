from django.urls import path
from .views import memorial_index

app_name = "memorials"

urlpatterns = [
    path("", memorial_index, name="index"),
]
