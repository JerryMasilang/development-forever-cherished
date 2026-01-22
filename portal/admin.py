from django.contrib import admin
from .models import DistributorApplication


# Register your models here.
@admin.register(DistributorApplication)
class DistributorApplicationAdmin(admin.ModelAdmin):
    list_display = (
        "full_name",
        "email",
        "company_name",
        "location",
        "status",
        "created_at",
    )
    list_filter = ("status", "created_at")
    search_fields = ("full_name", "email", "company_name")
    ordering = ("-created_at",)
