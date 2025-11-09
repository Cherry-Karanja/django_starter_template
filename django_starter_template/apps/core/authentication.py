"""
Custom authentication classes for the core app
"""
from rest_framework.authentication import SessionAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from drf_spectacular.extensions import OpenApiAuthenticationExtension


class CSRFExemptSessionAuthentication(SessionAuthentication):
    """
    Session authentication that exempts CSRF validation for API endpoints.

    This is useful for API-only endpoints where CSRF protection is not needed
    because we're using JWT tokens as the primary authentication method.
    """

    def enforce_csrf(self, request):
        """
        Override to disable CSRF validation for API endpoints.
        """
        return  # Do not enforce CSRF


class CustomJWTCookieAuthentication(JWTAuthentication):
    """
    Custom JWT cookie authentication that properly returns (user, validated_token)
    instead of (user, user.id) to ensure get_user receives the token payload.
    """

    def get_raw_token(self, request):
        """
        Get the raw token from cookies.
        """
        return request.COOKIES.get('access_token') or request.COOKIES.get('access')

    def authenticate(self, request):
        """
        Authenticate the request using JWT token from cookies.
        """
        raw_token = self.get_raw_token(request)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        user = self.get_user(validated_token)
        return (user, validated_token)


class CustomJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication that properly returns (user, validated_token)
    instead of (user, user.id) to ensure get_user receives the token payload.
    """

    def authenticate(self, request):
        """
        Authenticate the request using JWT token from header.
        """
        raw_token = self.get_raw_token(request)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        user = self.get_user(validated_token)
        return (user, validated_token)


class CSRFExemptSessionAuthenticationScheme(OpenApiAuthenticationExtension):
    """
    OpenAPI authentication extension for CSRFExemptSessionAuthentication.
    This provides the schema definition for the custom session authentication.
    """
    target_class = 'apps.core.authentication.CSRFExemptSessionAuthentication'
    name = 'SessionAuth'

    def get_security_definition(self, auto_schema):
        return {
            'type': 'apiKey',
            'in': 'cookie',
            'name': 'sessionid',
            'description': 'Session authentication using Django session cookies'
        }