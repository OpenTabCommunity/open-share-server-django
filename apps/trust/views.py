from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .models import TrustRoot
from .serializers import TrustRootSerializer


class TrustRootView(APIView):
    """
    GET /trustroot
    Returns the current server trust roots and supported protocol versions
    """

    def get(self, request):
        trust_roots = TrustRoot.objects.filter(active=True)
        serializer = TrustRootSerializer(trust_roots, many=True)

        data = {
            "trust_roots": serializer.data,
            "min_protocol_version": "1.0.0",
            "max_protocol_version": "1.2.0",
        }
        return Response(data, status=status.HTTP_200_OK)
