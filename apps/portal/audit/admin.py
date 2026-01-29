from django.contrib import admin
from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("id", "actor", "target_user", "created_at")
    list_filter = ("created_at",)


    search_fields = ("actor__username", "target_user__username")
