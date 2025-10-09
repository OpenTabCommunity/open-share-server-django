from rest_framework import serializers
from .models import Account


class AccountRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = Account
        fields = ("email", "password", "display_name")

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        account = Account.objects.create_user(password=password, **validated_data)
        return account
