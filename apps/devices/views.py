import base64
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import CrlEntries, Crls, CurrentCrl
from cryptography.hazmat.primitives.asymmetric import ed25519
import json
import os
from datetime import timedelta
from django.utils import timezone
from django.db import transaction
from rest_framework.permissions import IsAuthenticated
from .models import Device, DeviceCerts
from rest_framework import status
from openshare.settings import ED25519_PRIVATE_KEY_B64
from apps.accounts.models import Account

SERVER_ISSUER_ID = "openshare"  # TODO: set this in settings
PRIVATE_KEY_PATH = "openshare/settings/ED25519_PRIVATE_KEY_B64"


class DeviceRegisterView(APIView):
   # permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request):
        data = request.data
        account_email = data.get("email")
        device_uid = data.get("device_uid")
        pubkey_b64 = data.get("pubkey_ed25519")
        metadata = data.get("metadata", {})

        try:
            acc = Account.objects.get(email=account_email)
        except Account.DoesNotExist:
            return Response({"error": "User not found"}, status=404)

        if not device_uid or not pubkey_b64:
            return Response({"error": "device_uid and pubkey_ed25519 required"}, status=400)

        if Device.objects.filter(device_uid=device_uid, account_id=acc).exists():
            return Response({"error": "Device already registered"}, status=400)

        try:
            pubkey_bytes = base64.urlsafe_b64decode(pubkey_b64)
        except Exception:
            return Response({"error": "Invalid pubkey format"}, status=400)

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

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(ED25519_PRIVATE_KEY_B64.encode('utf-8'))

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
        return Response(cert_blob, status=201)


class DeviceRevokeView(APIView):
   # permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request):
        device_id = request.data.get("device_id")
        reason = request.data.get("reason", "revoked")

        if not device_id:
            return Response({"error": "device_id is required"}, status=400)

        try:
            device = Device.objects.get(id=device_id)
        except Device.DoesNotExist:
            return Response({"error": "Device not found"}, status=404)

        if device.status == "revoked":
            return Response({"message": "Device already revoked"}, status=400)

        device.status = "revoked"
        device.save(update_fields=["status"])

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(ED25519_PRIVATE_KEY_B64.encode('utf-8'))

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

        return Response({
            "status": "revoked",
            "device_id": str(device.id),
            "crl_version": crl.version,
            "signature": signature.hex()
        })


class LastCrl(APIView):
    #permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            current = CurrentCrl.objects.select_related(None).first()
            if not current or not current.crl_id:
                return Response(
                    {"detail": "No CRL available."},
                    status=status.HTTP_404_NOT_FOUND
                )

            crl = Crls.objects.get(id=current.id)

            response = Response(
                crl.crl_blob,
                status=status.HTTP_200_OK
            )
            response["ETag"] = str(crl.version)
            response["Cache-Control"] = "no-cache"

            return response

        except Crls.DoesNotExist:
            return Response(
                {"detail": "CRL not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
