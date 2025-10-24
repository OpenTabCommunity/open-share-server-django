from rest_framework import serializers
from .models import TrustRoot


class TrustRootSerializer(serializers.ModelSerializer):
    pubkey_ed25519 = serializers.SerializerMethodField()

    class Meta:
        model = TrustRoot
        fields = ["key_id", "pubkey_ed25519", "valid_from", "valid_to"]

    def get_pubkey_ed25519(self, obj):
        import base64
        return base64.urlsafe_b64encode(obj.pubkey_ed25519).decode("ascii")
