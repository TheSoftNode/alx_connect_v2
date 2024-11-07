from django.urls import re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

# Swagger schema view configuration
schema_view = get_schema_view(
   openapi.Info(
      title="ALX Connect API",
      default_version='v1',
      description="API documentation for the ALX Connect project",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@alxconnect.com"),
      license=openapi.License(name="MIT License"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)

from . import views

urlpatterns = [
    re_path('token/access', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    re_path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    re_path('signup', views.signup),
    re_path('login', views.login),
    re_path('test_token', views.test_token),
    re_path('verify-email', views.verify_email, name='verify-email'),
    re_path('request-password-reset', views.request_password_reset, name='request-password-reset'),
    re_path('reset-password', views.reset_password, name='reset-password'),
    re_path('change-password', views.change_password, name='change-password'),
    re_path('resend-verification', views.resend_verification, name='resend-verification'),
    # Swagger URLs
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    re_path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]