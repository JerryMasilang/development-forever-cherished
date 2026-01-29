from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("", include(("apps.website.landing.urls", "landing"), namespace="landing")),
    path("memorials/", include(("apps.website.memorials.urls", "memorials"), namespace="memorials")),
    path("portal/", include(("portal.urls", "portal"), namespace="portal")),
    path("admin/", admin.site.urls),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

