from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from apps.trust.views import TrustRootView
urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("apps.accounts.urls")),   # /account/* mapped by accounts/urls
    path("", include("apps.devices.urls")),
    path("trustroot", TrustRootView.as_view(), name="trustroot"),

    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
]
