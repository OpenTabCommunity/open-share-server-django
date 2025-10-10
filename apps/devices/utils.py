import base64
import json
from datetime import timedelta
from django.utils import timezone
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
from uuid import uuid4
from openshare import settings #TODO: fix this


def issue_device_cert(device_id: str, account_id: str, pubkey: bytes, sigkey:bytes, metadata: dict):
    key = SigningKey(base64.b64decode(settings, "ED255_PRIVATE_KEY_B64"))
    now = timezone.now()
    expires = now + settings.CERT_EXPIRE_TIME
    serial = str(uuid4())

    cert_body = {
      "device_id": device_id,
      "account_id": account_id,
      "pubkey_ed25519": base64.b64encode(pubkey).decode("ascii"),
      "issued_at": now.isoformat(),
      "expires_at": expires.isoformat(),
      "sig": base64.b64encode(sigkey).decode("ascii"),
      "meta": metadata or {}
    }

    cert_bytes = json.dumps(cert_body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signed = key.sign(cert_bytes, encoder=RawEncoder)
    signature = signed.signature

    cert_body_with_sig = cert_body.copy()
    cert_body_with_sig["signature"] = base64.b64encode(signature).decode("ascii")

    return cert_body_with_sig, signature
