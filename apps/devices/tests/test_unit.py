import pytest
from base64 import b64encode
from ..models import Device, DeviceCerts
import json
import uuid
from django.utils import timezone
from django.urls import reverse
from rest_framework.test import APIClient
from ..models import Crls, CrlEntries, CurrentCrl
from apps.accounts.models import Account

pytestmark = pytest.mark.django_db

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def account(user_factory):
    return user_factory()

@pytest.fixture
def auth_headers(account):
    token = "valid_api_token_for_testing"
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}

def test_device_register_success(api_client, auth_headers, account):
    payload = {
        "device_id": "test-device-001",
        "pubkey_ed25519": b64encode(b"this_is_a_fake_public_key_32b").decode(),
        "metadata": {"os": "linux", "version": "1.0.0"}
    }

    response = api_client.post("/device/register", data=json.dumps(payload),
                               content_type="application/json", **auth_headers)

    assert response.status_code == 201, response.content
    data = response.json()

    assert "cert_blob" in data
    assert "cert_sig" in data
    assert Device.objects.filter(device_uid="test-device-001").exists()
    assert DeviceCerts.objects.count() == 1

def test_device_register_duplicate(api_client, auth_headers, account):
    Device.objects.create(
        device_uid="dup-device",
        account_id=account.id,
        pubkey_ed25519=b"fake_key_1"
    )

    payload = {
        "device_id": "dup-device",
        "pubkey_ed25519": b64encode(b"fake_key_2").decode(),
        "metadata": {"os": "android"}
    }

    response = api_client.post("/device/register", data=json.dumps(payload),
                               content_type="application/json", **auth_headers)

    assert response.status_code == 400
    assert "already exists" in response.json()["error"].lower()

def test_device_register_invalid_schema(api_client, auth_headers):
    payload = {
        "device_id": "bad-device",
    }

    response = api_client.post("/device/register", data=json.dumps(payload),
                               content_type="application/json", **auth_headers)

    assert response.status_code == 400
    assert "missing" in response.json()["error"].lower()

def test_device_cert_generated(api_client, auth_headers, account):
    payload = {
        "device_id": "signed-device",
        "pubkey_ed25519": b64encode(b"test_pubkey_bytes_32").decode(),
        "metadata": {}
    }

    response = api_client.post("/device/register", data=json.dumps(payload),
                               content_type="application/json", **auth_headers)
    data = response.json()

    device = Device.objects.get(device_uid="signed-device")

    assert device.status == "active"
    assert device.cert_blob is not None
    assert isinstance(device.cert_issued_at, timezone.datetime)
    assert data["cert_blob"]["device_id"] == "signed-device"



def test_device_revoke(db):

    client = APIClient()
    account = Account.objects.create(
        id=uuid.uuid4(),
        name="Armin",
        email="armin@example.com",
        api_token="testtoken123",
    )

    device = Device.objects.create(
        id=uuid.uuid4(),
        device_uid="dev-001",
        account=account,
        status="active",
        pubkey_ed25519=b"0" * 32,
        metadata={"os": "linux"},
        created_at=timezone.now(),
        updated_at=timezone.now(),
    )

    cert = DeviceCerts.objects.create(
        device=device,
        cert_blob={"device_id": device.device_uid},
        cert_sig=b"x" * 64,
        issued_at=timezone.now(),
        expires_at=timezone.now() + timezone.timedelta(days=90),
        issuer_id="server-1",
    )

    crl = Crls.objects.create(
        version=1,
        issuer_id="server-1",
        issued_at=timezone.now(),
        crl_blob={"revoked": []},
        sig=b"x" * 64,
        notes="Initial empty CRL",
    )
    CurrentCrl.objects.create(id=1, crl_id=crl.id)

    data = {
        "device_id": str(device.id),
        "reason": "Key compromised",
    }

    response = client.post(
        reverse("device-revoke"),
        data=json.dumps(data),
        content_type="application/json",
        HTTP_AUTHORIZATION="Bearer testtoken123",
    )

    assert response.status_code == 200

    device.refresh_from_db()
    assert device.status == "revoked"

    new_crl = Crls.objects.latest("id")
    assert new_crl.version == 2
    assert "revoked" in new_crl.crl_blob

    entry = CrlEntries.objects.filter(revoked_device_id=device.id).first()
    assert entry is not None
    assert entry.reason == "Key compromised"

    current = CurrentCrl.objects.get(id=1)
    assert current.crl_id == new_crl.id