from django.urls import path
from apps.accounts.views import AccountRegisterView, AccountDevicesView

urlpatterns = [
    path("account/register", AccountRegisterView.as_view(), name="createAccount"),
    path("account/devices", AccountDevicesView.as_view(), name="listDevices"),
]
