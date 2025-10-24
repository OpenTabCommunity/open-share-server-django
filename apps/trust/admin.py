from django.contrib import admin
from .models import TrustRoot


@admin.register(TrustRoot)
class TrustRootAdmin(admin.ModelAdmin):
    list_display = ("key_id", "valid_from", "valid_to", "active")
    list_filter = ("active",)
    search_fields = ("key_id",)
    readonly_fields = ("key_id",)
