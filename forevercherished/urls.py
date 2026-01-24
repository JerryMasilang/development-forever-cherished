from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.conf import settings
from django.conf.urls.static import static

def root_redirect(request):
    return redirect("portal:dashboard")


urlpatterns = [
    path("", root_redirect),  # 👈 THIS LINE FIXES THE 404
    path("portal/", include(("portal.urls", "portal"), namespace="portal")),
    path("admin/", admin.site.urls),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
