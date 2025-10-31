import base64
import json
from datetime import timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.db import transaction
from django.utils import timezone
from apps.accounts.models import Account
from openshare.settings import ED25519_PRIVATE_KEY_B64
from openshare.settings import SERVER_ISSUER_ID
from .models import CrlEntries, Crls, CurrentCrl
from .models import Device, DeviceCerts


@transaction.atomic
def device_register(account_email: str, device_uid: str, pubkey_b64: str, metadata: {}):
    acc = Account.objects.get(email=account_email)
    pubkey_bytes = base64.urlsafe_b64decode(pubkey_b64)
    issued_at = timezone.now()
    expires_at = issued_at + timedelta(days=365)

    cert_blob = {
        "device_uid": device_uid,
        "account_id": str(acc),
        "issuer": SERVER_ISSUER_ID,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "pubkey_ed25519": pubkey_b64,
        "metadata": metadata
    }
    cert_json = json.dumps(cert_blob, sort_keys=True).encode()

    private_key_bytes = base64.urlsafe_b64decode(ED25519_PRIVATE_KEY_B64 + "==")
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature = private_key.sign(cert_json)

    device = Device.objects.create(
        device_uid=device_uid,
        account_id=acc,
        status="active",
        pubkey_ed25519=pubkey_bytes,
        pubkey_b64=pubkey_b64,
        cert_blob=cert_blob,
        cert_sig=signature,
        cert_issued_at=issued_at,
        cert_expires_at=expires_at,
        metadata=metadata
    )

    DeviceCerts.objects.create(
        device_id=device,
        cert_blob=cert_blob,
        cert_sig=signature,
        issued_at=issued_at,
        expires_at=expires_at,
        issuer_id=SERVER_ISSUER_ID
    )

    cert_blob["signature"] = signature.hex()
    return cert_blob


@transaction.atomic
def device_revoke(device_id, reason):
    device = Device.objects.get(id=device_id)
    device.status = "revoked"
    device.save(update_fields=["status"])

    private_key_bytes = base64.urlsafe_b64decode(ED25519_PRIVATE_KEY_B64 + "==")
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)

    revoked_devices = Device.objects.filter(status="revoked")
    revoked_entries = [
        {
            "device_id": str(d.id),
            "revoked_at": timezone.now().isoformat(),
            "reason": "revoked"
        }
        for d in revoked_devices
    ]

    crl_blob = {
        "issuer": "server-ca",
        "issued_at": timezone.now().isoformat(),
        "entries": revoked_entries
    }
    crl_json = json.dumps(crl_blob, sort_keys=True).encode()

    signature = private_key.sign(crl_json)

    last_crl = Crls.objects.order_by("-version").first()
    new_version = (last_crl.version + 1) if last_crl else 1

    crl = Crls.objects.create(
        version=new_version,
        issuer_id="server-ca",
        crl_blob=crl_blob,
        sig=signature
    )

    CrlEntries.objects.create(
        crl_id=crl,
        revoked_device_id=device,
        reason=reason
    )

    CurrentCrl.objects.update_or_create(
        id=1,
        defaults={"crl_id": crl, "updated_at": timezone.now()}
    )

    return ({
        "status": "revoked",
        "device_id": str(device.id),
        "crl_version": crl.version,
        "signature": signature.hex()
    })

