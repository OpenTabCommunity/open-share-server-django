from django.utils import timezone
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from apps.trust.models import TrustRoot


class TrustRootTests(APITestCase):
    def setUp(self):
        TrustRoot.objects.create(
            key_id="root-001",
            pubkey_ed25519=b"\x01" * 32,
            valid_from=timezone.now(),
            valid_to=timezone.now() + timezone.timedelta(days=365),
            active=True
        )

    def test_get_trustroot(self):
        response = self.client.get("/trustroot")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("trust_roots", response.data)
        self.assertEqual(len(response.data["trust_roots"]), 1)
        self.assertIn("pubkey_ed25519", response.data["trust_roots"][0])
