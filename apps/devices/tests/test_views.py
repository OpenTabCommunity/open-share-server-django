import base64
import json
import uuid

from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.test import APITestCase

from apps.accounts.models import Account
from apps.devices.models import Device, Crls, CurrentCrl


class DeviceRegisterTest(APITestCase):

    def setUp(self):
        self.client = APIClient()
        self.account = Account.objects.create(
            account_id=uuid.uuid4(),
            display_name="Armin",
            email="a@example.com",
        )
        self.client.force_authenticate(user=self.account)

    def test_device_register_success(self):
        data = {
            "device_uid": "dev-001",
            "pubkey_ed25519": base64.b64encode(b"0" * 32).decode(),
            "metadata": {"os": "linux"},
            "email": self.account.email
        }

        response = self.client.post(
            reverse("device-register"),
            data,
            format='json'
        )

        self.assertEqual(response.status_code, 201)

    def test_device_register_duplicate_id(self):
        Device.objects.create(
            id=uuid.uuid4(),
            device_uid="dev-001",
            account_id=self.account,
            status="active",
            pubkey_ed25519=b"0" * 32,
            cert_issued_at=timezone.now()
        )

        data = {
            "device_uid": "dev-001",
            "pubkey_ed25519": base64.b64encode(b"1" * 32).decode(),
            "metadata": {"os": "linux"},
            "email": self.account.email
        }

        response = self.client.post(
            reverse("device-register"),
            data=json.dumps(data),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        assert "error" in response.json()

    def test_device_register_missing_field(self):
        data = {
            "email": self.account.email,
            "pubkey_ed25519": base64.b64encode(b"0" * 32).decode()  # device_id missing
        }

        response = self.client.post(
            reverse("device-register"),
            data=json.dumps(data),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        assert "error" in response.json()


class DeviceRevokeTest(APITestCase):

    def setUp(self):
        self.client = APIClient()
        self.account = Account.objects.create(
            account_id=uuid.uuid4(),
            display_name="Armin",
            email="a@example.com",
        )
        self.client.force_authenticate(user=self.account)

    def test_device_revoke_success(self):
        device = Device.objects.create(
            id=uuid.uuid4(),
            device_uid="dev-003",
            account_id=self.account,
            status="active",
            pubkey_ed25519=b"0" * 32,
            cert_issued_at=timezone.now(),
        )

        crl = Crls.objects.create(
            version=1,
            issuer_id="server-1",
            issued_at=timezone.now(),
            crl_blob={"revoked": []},
            sig=b"x" * 64,
            notes="Initial CRL"
        )
        CurrentCrl.objects.create(id=1, crl_id=crl)

        data = {"device_id": str(device.id), "reason": "Compromised"}

        response = self.client.post(
            reverse("device-revoke"),
            data=json.dumps(data),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        device.refresh_from_db()
        assert device.status == "revoked"

    def test_device_revoke_nonexistent(self):
        data = {"device_id": str(uuid.uuid4()), "reason": "Compromised"}

        response = self.client.post(
            reverse("device-revoke"),
            data=json.dumps(data),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 404)

    def test_device_revoke_already_revoked(self):
        device = Device.objects.create(
            id=uuid.uuid4(),
            device_uid="dev-004",
            account_id=self.account,
            status="revoked",
            pubkey_ed25519=b"0" * 32,
            cert_issued_at=timezone.now(),
        )

        data = {"device_id": str(device.id), "reason": "Compromised"}

        response = self.client.post(
            reverse("device-revoke"),
            data=json.dumps(data),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)


class CrlTest(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.account = Account.objects.create(
            account_id=uuid.uuid4(),
            display_name="Armin",
            email="a@example.com",
        )
        self.client.force_authenticate(user=self.account)

    def test_get_crl_success(self):
        crl = Crls.objects.create(
            version=10,
            issuer_id="server-1",
            issued_at=timezone.now(),
            crl_blob={"revoked": [{"device_id": "abc", "reason": "test"}]},
            sig=b"x" * 64,
            notes="Test CRL"
        )
        CurrentCrl.objects.update_or_create(id=1, crl_id=crl)
        response = self.client.get(reverse("device-crl"))
        self.assertEqual(response.status_code, 200)

    def test_get_crl_not_found(self):
        response = self.client.get(reverse("device-crl"))
        self.assertEqual(response.status_code, 404)
