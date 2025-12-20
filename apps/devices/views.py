import base64

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import Account
from apps.devices.models import Crls, CurrentCrl
from apps.devices.models import Device
from apps.devices.services import device_register, device_revoke


class DeviceRegisterView(APIView):
    permission_classes = [IsAuthenticated]

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
            base64.urlsafe_b64decode(pubkey_b64)
        except Exception:
            return Response({"error": "Invalid pubkey format"}, status=400)

        cert_blob = device_register(account_email=account_email,
                                    device_uid=device_uid,
                                    pubkey_b64=pubkey_b64,
                                    metadata=metadata
                                    )
        return Response(cert_blob, status=201)


class DeviceRevokeView(APIView):
    permission_classes = [IsAuthenticated]

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

        res = device_revoke(device_id=device_id, reason=reason)
        return Response(res, status=200)


class LastCrl(APIView):
    permission_classes = [IsAuthenticated]

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
