from django.urls import path
from .views import DeviceRevokeView
from .views import DeviceRegisterView
from .views import LastCrl

urlpatterns = [
    path("device/revoke", DeviceRevokeView.as_view(), name="device-revoke"),
    path("device/register", DeviceRegisterView.as_view(), name="device-register"),
    path("crl", LastCrl.as_view(), name="device-crl"),
]