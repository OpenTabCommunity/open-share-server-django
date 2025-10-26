from rest_framework import serializers
from .models import Device, DeviceCerts, Crls, CrlEntries, CurrentCrl


class DeviceListSerializer(serializers.ModelSerializer):

    class Meta:
        model = Device
        fields = [
            "id",
            "device_uid",
            "status",
            "cert_expires_at",
            "last_seen",
            "created_at",
        ]
