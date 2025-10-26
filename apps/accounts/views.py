from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .serializers import AccountRegisterSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Account
from apps.devices.models import Device
from apps.devices.serializers import DeviceListSerializer


class AccountRegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = AccountRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        account = serializer.save()
        # create token pair and return access token as api_token
        refresh = RefreshToken.for_user(account)
        access = refresh.access_token
        # add account claim
        access["account_id"] = str(account.account_id)
        return Response({
            "account_id": str(account.account_id),
            "api_token": str(access)
        }, status=status.HTTP_201_CREATED)


class AccountDevicesView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        account = request.user
        devices = Device.objects.filter(account=account)
        serializer = DeviceListSerializer(devices, many=True)
        return Response({"devices": serializer.data}, status=status.HTTP_200_OK)
