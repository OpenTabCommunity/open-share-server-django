import json
import base64
import uuid
from django.utils import timezone
from django.urls import reverse
from rest_framework.test import APIClient
from apps.devices.models import Device, Crls, CurrentCrl
from apps.accounts.models import Account


def test_device_register_success(db):
    client = APIClient()
    account = Account.objects.create(
        account_id=uuid.uuid4(),
        display_name="Armin",
        email="a@example.com",
    )
    client.force_authenticate(user=account)
    data = {
        "device_id": "dev-001",
        "pubkey_ed25519": base64.b64encode(b"0" * 32).decode(),
        "metadata": {"os": "linux"}
    }

    response = client.post(
        reverse("device-register"),
        data=json.dumps(data),
        content_type="application/json",
        #HTTP_AUTHORIZATION=f"Bearer {account.api_token}"
    )

    assert response.status_code == 201
    resp_json = response.json()
    assert "certificate" in resp_json


def test_device_register_duplicate_id(db):
    client = APIClient()
    account = Account.objects.create(
        account_id=uuid.uuid4(),
        display_name="Armin",
        email="a@example.com",
    )
    client.force_authenticate(user=account)
    Device.objects.create(
        id=uuid.uuid4(),
        device_uid="dev-001",
        account_id=account,
        status="active",
        pubkey_ed25519=b"0" * 32,
        cert_issued_at=timezone.now()
    )

    data = {
        "device_uid": "dev-001",
        "pubkey_ed25519": base64.b64encode(b"1" * 32).decode(),
        "metadata": {"os": "linux"}
    }

    response = client.post(
        reverse("device-register"),
        data=json.dumps(data),
        content_type="application/json",
        #HTTP_AUTHORIZATION=f"Bearer {account.api_token}"
    )

    assert response.status_code == 400
    assert "error" in response.json()




def test_device_register_missing_field(db):
    client = APIClient()
    account = Account.objects.create(
        account_id=uuid.uuid4(),
        display_name="Armin",
        email="a@example.com",
    )
    client.force_authenticate(user=account)
    data = {
        "pubkey_ed25519": base64.b64encode(b"0" * 32).decode()  # device_id missing
    }

    response = client.post(
        reverse("device-register"),
        data=json.dumps(data),
        content_type="application/json",
        #HTTP_AUTHORIZATION=f"Bearer {account.api_token}"
    )

    assert response.status_code == 400
    assert "error" in response.json()


def test_device_revoke_success(db):
    client = APIClient()
    account = Account.objects.create(
        account_id=uuid.uuid4(),
        display_name="Armin",
        email="a@example.com",
    )
    device = Device.objects.create(
        id=uuid.uuid4(),
        device_uid="dev-003",
        account_id=account,
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

    response = client.post(
        reverse("device-revoke"),
        data=json.dumps(data),
        content_type="application/json",
        #HTTP_AUTHORIZATION=f"Bearer {account.api_token}"
    )

    assert response.status_code == 200
    device.refresh_from_db()
    assert device.status == "revoked"


def test_device_revoke_nonexistent(db):
    client = APIClient()
    account = Account.objects.create(
        account_id=uuid.uuid4(),
        display_name="Armin",
        email="a@example.com",
    )
    data = {"device_id": str(uuid.uuid4()), "reason": "Compromised"}

    response = client.post(
        reverse("device-revoke"),
        data=json.dumps(data),
        content_type="application/json",
        #HTTP_AUTHORIZATION=f"Bearer {account.api_token}"
    )

    assert response.status_code == 404


def test_device_revoke_already_revoked(db):
    client = APIClient()
    account = Account.objects.create(
        account_id=uuid.uuid4(),
        display_name="Armin",
        email="a@example.com",
    )
    device = Device.objects.create(
        id=uuid.uuid4(),
        device_uid="dev-004",
        account_id=account,
        status="revoked",
        pubkey_ed25519=b"0" * 32,
        cert_issued_at=timezone.now(),
    )

    data = {"device_id": str(device.id), "reason": "Compromised"}

    response = client.post(
        reverse("device-revoke"),
        data=json.dumps(data),
        content_type="application/json",
        #HTTP_AUTHORIZATION=f"Bearer {account.api_token}"
    )

    assert response.status_code == 400



def test_get_crl_success(db):
    client = APIClient()
    crl = Crls.objects.create(
        version=10,
        issuer_id="server-1",
        issued_at=timezone.now(),
        crl_blob={"revoked": [{"device_id": "abc", "reason": "test"}]},
        sig=b"x" * 64,
        notes="Test CRL"
    )
    CurrentCrl.objects.create(id=1, crl_id=crl)

    response = client.get(reverse("device-crl"))

    assert response.status_code == 200
    resp_json = response.json()
    assert resp_json["revoked"][0]["device_id"] == "abc"
    assert response["ETag"] == str(crl.version)


def test_get_crl_not_found(db):
    client = APIClient()
    response = client.get(reverse("device-crl"))

    assert response.status_code == 404
