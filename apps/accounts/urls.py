from django.urls import path
from .views import AccountRegisterView, AccountDevicesView

urlpatterns = [
    path("register", AccountRegisterView.as_view(), name="createAccount"),
    path("devices", AccountDevicesView.as_view(), name="listDevices"),
]
