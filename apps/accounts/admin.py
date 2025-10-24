from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Account


@admin.register(Account)
class AccountAdmin(UserAdmin):
    model = Account
    list_display = ("email", "display_name", "is_active", "is_staff", "created_at")
    list_filter = ("is_active", "is_staff", "created_at")
    ordering = ("-created_at",)
    search_fields = ("email", "display_name")

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal info", {"fields": ("display_name",)}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Important dates", {"fields": ("last_login", "created_at")}),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "display_name", "password1", "password2", "is_active", "is_staff", "is_superuser"),
        }),
    )

    readonly_fields = ("created_at",)
