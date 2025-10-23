from django.urls import path
from .views import DeviceRevokeView
from .views import DeviceRegisterView

urlpatterns = [
    path("device/revoke", DeviceRevokeView.as_view(), name="device-revoke"),
    path("device/register", DeviceRegisterView.as_view(), name="device-register"),
]