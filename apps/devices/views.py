# myapp/api.py
import base64
import json
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from jsonschema import validate as jsonschema_validate, ValidationError as JSONSchemaValidationError

from apps.accounts.models import Account
from .models import Device, DeviceCerts
from .utils import issue_device_cert

DEVICE_REGISTER_SCHEMA = {
    "title": "Device Certificate",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "device_id": {"type": "string", "description": "Unique device identifier"},
        "account_id": {"type": "string", "description": "Account this device belongs to"},
        "pubkey_ed25519": {"type": "string", "description": "Base64url encoded Ed25519 public key"},
        "issued_at": {"type": "string", "format": "date-time"},
        "expires_at": {"type": "string", "format": "date-time"},
        "sig": {"type": "string", "description": "Base64url Ed25519 signature over canonicalized cert fields"},
        "meta": {"type": "object", "additionalProperties": True,
                 "description": "Optional free-form metadata (OS, client version, device name)"}
    },
    "required": ["device_id", "account_id", "pubkey_ed25519", "issued_at", "expires_at", "sig"],
}


class BearerTokenPermission(permissions.BasePermission):

    def authenticate_token(self, token):
        try:
            return Account.objects.get(user__auth_token__key=token)
        except Account.DoesNotExist:
            return None

    def has_permission(self, request, view):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        token = auth.split(" ", 1)[1].strip()
        account = self.authenticate_token(token)
        if not account:
            return False
        request.account = account
        return True


class DeviceRegisterView(APIView):
    permission_classes = [BearerTokenPermission]

    def post(self, request, *args, **kwargs):
        try:
            payload = request.data
            jsonschema_validate(instance=payload, schema=DEVICE_REGISTER_SCHEMA)
        except JSONSchemaValidationError as e:
            return Response({"error": "invalid_schema", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        device_id = payload.get("device_id")
        pubkey_ed25519 = payload.get("pubkey_ed25519")
        metadata = payload.get("metadata", {})

        try:
            pubkey_bytes = base64.b64decode(pubkey_ed25519)
        except Exception:
            return Response({"error": "invalid_pubkey_base64"}, status=status.HTTP_400_BAD_REQUEST)

        if len(pubkey_bytes) != 32:
            return Response({"error": "invalid_pubkey_length", "expected": 32, "actual": len(pubkey_bytes)},
                            status=status.HTTP_400_BAD_REQUEST)

        account = request.account

        # Device with same device id for this account must not exist TODO: check account field
        if Device.objects.filter(account=account, device_id=device_id).exists():
            return Response({"error": "device_id_already_exists"}, status=status.HTTP_409_CONFLICT)

        # issue cert
        cert_json, signature = issue_device_cert(device_id=device_id, pubkey=pubkey_bytes,
                                                        metadata=metadata, sigkey="", account_id=account.account_id)

        issued_at = timezone.datetime.fromisoformat(cert_json["issued_at"])
        expires_at = timezone.datetime.fromisoformat(cert_json["expires_at"])

        # create Device and store pubkey
        device = Device.objects.create(account=account,
                                       device_uid=device_id,
                                       account_id = account.account_id,
                                       pubkey_ed25519 = pubkey_ed25519,
                                       pubkey_b64 = pubkey_bytes,
                                       cert_sig = signature,
                                       cert_issued_at = issued_at,
                                       cert_expires_at = expires_at,
                                       status="active",
                                       metadata=metadata,
                                       )

        DeviceCerts.objects.create(device=device,
                                   cert_blob=cert_json,
                                   cert_sig=signature,
                                   issued_at=issued_at,
                                   expires_at=expires_at,
                                   )



        return Response(cert_json, status=status.HTTP_201_CREATED)
