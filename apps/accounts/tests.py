from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from .models import Account
from devices.models import Device
from rest_framework_simplejwt.tokens import RefreshToken


class AccountRegisterTests(APITestCase):
    def test_register_new_account(self):
        """
        New account test with POST /account/register
        """
        url = "/account/register"
        data = {
            "email": "testuser@example.com",
            "password": "secret123",
            "display_name": "Test User"
        }
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("account_id", response.data)
        self.assertIn("api_token", response.data)

        # Checking DB
        self.assertTrue(Account.objects.filter(email="testuser@example.com").exists())


class AccountDevicesTests(APITestCase):
    def setUp(self):
        # Test User Creation
        self.account = Account.objects.create_user(
            email="devices@example.com",
            password="testpass",
            display_name="Device Tester"
        )
        refresh = RefreshToken.for_user(self.account)
        self.token = str(refresh.access_token)

    def test_get_devices_list_empty(self):
        """
        Checking device lists when nothing saved
        """
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        url = "/account/devices"

        response = client.get(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("devices", response.data)
        self.assertEqual(len(response.data["devices"]), 0)

    def test_get_devices_list_with_one_device(self):
        """
        Checking device list when one device exists for account
        """
        Device.objects.create(
            account=self.account,
            device_id="test-dev-1",
            pubkey_ed25519=b"\x00" * 32
        )

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        url = "/account/devices"

        response = client.get(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["devices"]), 1)
        self.assertEqual(response.data["devices"][0]["device_id"], "test-dev-1")
