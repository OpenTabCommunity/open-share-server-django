from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework import permissions

from apps.trust.models import TrustRoot
from apps.trust.serializers import TrustRootSerializer


class TrustRootView(APIView):
    """
    GET /trustroot
    Returns the current server trust roots and supported protocol versions
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        trust_roots = TrustRoot.objects.filter(active=True)
        serializer = TrustRootSerializer(trust_roots, many=True)

        data = {
            "trust_roots": serializer.data,
            "min_protocol_version": "1.0.0",
            "max_protocol_version": "1.2.0",
        }
        return Response(data, status=status.HTTP_200_OK)
