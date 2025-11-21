"""
Custom authentication views with proper API documentation tags
"""
from rest_framework import serializers, status
from rest_framework.response import Response
from django.utils import timezone
from django.contrib.auth import logout as django_logout
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from dj_rest_auth.app_settings import api_settings
from dj_rest_auth.views import (
    LoginView as BaseLoginView,
    LogoutView as BaseLogoutView,
    UserDetailsView as BaseUserDetailsView,
    PasswordChangeView as BasePasswordChangeView,
    PasswordResetView as BasePasswordResetView,
    PasswordResetConfirmView as BasePasswordResetConfirmView,
)
from dj_rest_auth.registration.views import (
    RegisterView as BaseRegisterView,
    VerifyEmailView as BaseVerifyEmailView,
    ResendEmailVerificationView as BaseResendEmailVerificationView,
)
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiResponse
from drf_spectacular.types import OpenApiTypes
from .serializers import (
    PasswordResetConfirmSerializer,
    PasswordResetConfirmResponseSerializer,
    PasswordResetSerializer
)
from rest_framework_simplejwt.views import TokenRefreshView
from .services import TwoFactorAuthService
from .serializers import (
    CustomRegisterSerializer, CustomLoginSerializer,
    TwoFactorSetupSerializer, TwoFactorVerifySerializer, TwoFactorVerifyLoginSerializer,
    TwoFactorStatusSerializer, TwoFactorBackupCodesSerializer,
    CustomTokenRefreshSerializer
)

from apps.core.utils import get_client_ip
from django.utils import timezone
from rest_framework import status, permissions, views, filters, generics
from rest_framework.response import Response

# Create a custom TokenRefreshView with proper tags
class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom token refresh view that uses cookies for refresh tokens.
    """
    serializer_class = CustomTokenRefreshSerializer

    @extend_schema(
        tags=['Authentication'],
        summary="Refresh JWT token",
        description="Refresh JWT access token using refresh token from httpOnly cookies. No request body required.",
    )
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        # Set the new access token in cookie if refresh was successful
        if response.status_code == 200 and 'access' in response.data:
            from dj_rest_auth.jwt_auth import set_jwt_access_cookie
            set_jwt_access_cookie(response, response.data['access'])
            
        return response


# Simple response serializers for API documentation
class LogoutResponseSerializer(serializers.Serializer):
    """Serializer for logout response"""
    detail = serializers.CharField(default="Successfully logged out.")


class MessageResponseSerializer(serializers.Serializer):
    """Generic message response serializer"""
    detail = serializers.CharField()
    message = serializers.CharField(required=False)


@extend_schema(
    tags=["Authentication"],
    summary="Custom user login",
    description="Login with email and password.",
    request=CustomLoginSerializer,
    responses={200: OpenApiTypes.OBJECT, 400: {"description": "Invalid credentials"}}
)
class LoginView(BaseLoginView):
    """Custom login view with 2FA support"""
    serializer_class = CustomLoginSerializer

    def post(self, request, *args, **kwargs):
        """Handle login with 2FA support"""
        # First, perform normal login
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            # Login successful, check if 2FA is required
            user = request.user
            if user.is_otp_enabled() and user.otp_device.confirmed:
                # 2FA is enabled, return special response indicating 2FA required
                # Don't return the normal JWT tokens
                return Response({
                    'detail': '2FA verification required',
                    'requires_2fa': True,
                    'user_id': user.id
                }, status=status.HTTP_200_OK)

        return response


@extend_schema(
    tags=['Authentication'],
    summary="User logout",
    description="Logout user and blacklist JWT refresh token. Reads refresh token from httpOnly cookies automatically. No request body required.",
    responses={
        200: LogoutResponseSerializer,
        401: {"description": "Refresh token was not found in cookies or is invalid."}
    }
)
class LogoutView(BaseLogoutView):
    """
    Custom logout view with proper API documentation
    """
    serializer_class = LogoutResponseSerializer
    allowed_methods = ['POST']

    def logout(self, request):
        """
        Override the logout method to read refresh token from cookies
        instead of request data, since httpOnly cookies cannot be accessed by frontend.
        """
        try:
            request.user.auth_token.delete()
        except (AttributeError, ObjectDoesNotExist):
            pass

        if api_settings.SESSION_LOGIN:
            django_logout(request)

        response = Response(
            {'detail': _('Successfully logged out.')},
            status=status.HTTP_200_OK,
        )

        if api_settings.USE_JWT:
            # NOTE: this import occurs here rather than at the top level
            # because JWT support is optional, and if `USE_JWT` isn't
            # True we shouldn't need the dependency
            from rest_framework_simplejwt.exceptions import TokenError
            from rest_framework_simplejwt.tokens import RefreshToken

            from dj_rest_auth.jwt_auth import unset_jwt_cookies
            cookie_name = api_settings.JWT_AUTH_COOKIE

            unset_jwt_cookies(response)

            if 'rest_framework_simplejwt.token_blacklist' in settings.INSTALLED_APPS:
                # add refresh token to blacklist - read from cookies instead of request.data
                try:
                    refresh_token = request.COOKIES.get('refresh')
                    if not refresh_token:
                        response.data = {'detail': _('Refresh token was not found in cookies.')}
                        response.status_code = status.HTTP_401_UNAUTHORIZED
                        return response
                    
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                except KeyError:
                    response.data = {'detail': _('Refresh token was not included in request data.')}
                    response.status_code = status.HTTP_401_UNAUTHORIZED
                except (TokenError, AttributeError, TypeError) as error:
                    if hasattr(error, 'args'):
                        if 'Token is blacklisted' in error.args or 'Token is invalid or expired' in error.args:
                            response.data = {'detail': _(error.args[0])}
                            response.status_code = status.HTTP_401_UNAUTHORIZED
                        else:
                            response.data = {'detail': _('An error has occurred.')}
                            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

                    else:
                        response.data = {'detail': _('An error has occurred.')}
                        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

            elif not cookie_name:
                message = _(
                    'Neither cookies or blacklist are enabled, so the token '
                    'has not been deleted server side. Please make sure the token is deleted client side.',
                )
                response.data = {'detail': message}
                response.status_code = status.HTTP_200_OK
        return response


@extend_schema(
    tags=['Authentication'],
    summary="User registration",
    description="Register new user accounts with email verification.",
    request=CustomRegisterSerializer
)
class RegisterView(BaseRegisterView):
    """
    Custom registration view with proper API documentation
    """
    serializer_class = CustomRegisterSerializer

    @extend_schema(
        tags=['Authentication'],
        summary="User registration",
        description="Register a new user account. Creates user profile and assigns appropriate role.",
        request=OpenApiTypes.OBJECT,
        responses={201: OpenApiTypes.OBJECT, 400: OpenApiTypes.OBJECT}
    )
    def post(self, request, *args, **kwargs):
        from django.db import IntegrityError
        from rest_framework.response import Response
        from rest_framework import status
        import logging
        logger = logging.getLogger(__name__)
        try:
            response = super().post(request, *args, **kwargs)
            # If the response is already an error, just return it
            if hasattr(response, 'data') and response.status_code == 400 and 'non_field_errors' in response.data:
                return Response(response.data, status=status.HTTP_400_BAD_REQUEST)
            return response
        except Exception as e:
            logger.error(f"Registration error: {e}")
            if isinstance(e, IntegrityError) or 'UNIQUE constraint failed' in str(e):
                if 'auth_user.email' in str(e):
                    return Response(
                        {'email': ['A user with this email address already exists.']},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    return Response(
                        {'error': ['Registration failed due to a data conflict. Please try again.']},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            # If the exception has a 'detail' or 'args' with serializer errors, return them
            if hasattr(e, 'detail'):
                return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
            if hasattr(e, 'args') and e.args and isinstance(e.args[0], dict):
                return Response(e.args[0], status=status.HTTP_400_BAD_REQUEST)
            return Response(
                {'error': ['Registration failed. Please check your information and try again.']},
                status=status.HTTP_400_BAD_REQUEST
            )


@extend_schema(
    tags=['Users'],
    summary="User profile management",
    description="Get and update current user's profile information."
)
class UserDetailsView(BaseUserDetailsView):
    """
    Custom user details view with proper API documentation
    """

    @extend_schema(
        tags=['Users'],
        summary="Get user details",
        description="Get current authenticated user's profile information.",
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        tags=['Users'],
        summary="Update user details",
        description="Update current authenticated user's profile information.",
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @extend_schema(
        tags=['Users'],
        summary="Partially update user details",
        description="Partially update current authenticated user's profile information.",
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="Password management",
    description="Change user password with current password verification."
)
class PasswordChangeView(BasePasswordChangeView):
    """
    Custom password change view with proper API documentation
    """

    @extend_schema(
        tags=['Authentication'],
        summary="Change password",
        description="Change user's password. Requires current password for verification.",
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="Password reset",
    description="Request password reset via email."
)
class PasswordResetView(BasePasswordResetView):
    """
    Custom password reset view with proper API documentation and custom form
    """

    def get_serializer_class(self):
        """
        Return the custom password reset serializer
        """
        return PasswordResetSerializer

    @extend_schema(
        tags=['Authentication'],
        summary="Request password reset",
        description="Send password reset email to user.",
        responses={200: MessageResponseSerializer}
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="Password reset confirmation",
    description="Confirm password reset with token and set new password."
)
class PasswordResetConfirmView(BasePasswordResetConfirmView):
    """
    Custom password reset confirm view with proper API documentation

    Accepts the following POST parameters:
    - uid: User ID (base36 encoded)
    - token: Password reset token
    - new_password1: New password
    - new_password2: New password confirmation

    Returns success message when password is reset successfully.
    """
    serializer_class = PasswordResetConfirmSerializer

    def get_serializer(self, *args, **kwargs):
        data = self.request.data.copy()
        data['uid'] = self.kwargs.get('uid')
        data['token'] = self.kwargs.get('token')
        kwargs['data'] = data
        return super().get_serializer(*args, **kwargs)

    @extend_schema(
        tags=['Authentication'],
        summary="Confirm password reset",
        description="Confirm password reset with token and set new password. "
                   "This endpoint validates the reset token and sets a new password for the user.",
        request=PasswordResetConfirmSerializer,
        parameters=[
            OpenApiParameter("uid", OpenApiTypes.STR, location=OpenApiParameter.PATH, description="User ID (base36 encoded)"),
            OpenApiParameter("token", OpenApiTypes.STR, location=OpenApiParameter.PATH, description="Password reset token"),
        ],
        responses={
            200: PasswordResetConfirmResponseSerializer,
            400: OpenApiTypes.OBJECT,  # Use OpenApiTypes.OBJECT for generic error responses
        }
    )
    def post(self, request, *args, **kwargs):
        """
        Confirm password reset and set new password.

        This method handles the password reset confirmation process by:
        1. Validating the provided uid and token
        2. Checking the new password meets requirements
        3. Setting the new password for the user
        4. Returning a success response
        """
        return super().post(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="Email verification",
    description="Verify user email addresses with verification tokens."
)
class VerifyEmailView(BaseVerifyEmailView):
    """
    Custom email verification view with proper API documentation
    """

    @extend_schema(
        tags=['Authentication'],
        summary="Verify email",
        description="Verify user's email address with verification token.",
        responses={200: MessageResponseSerializer}
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="Email verification resend",
    description="Resend email verification tokens to users."
)
class ResendEmailVerificationView(BaseResendEmailVerificationView):
    """
    Custom resend email verification view with proper API documentation
    """

    @extend_schema(
        tags=['Authentication'],
        summary="Resend email verification",
        description="Resend email verification token to user.",
        responses={200: MessageResponseSerializer}
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)
    
    
# Two-Factor Authentication Views
@extend_schema(
    tags=["Two-Factor Authentication"],
    summary="Setup 2FA",
    description="Initialize two-factor authentication setup for the current user.",
    responses={200: TwoFactorSetupSerializer}
)
class TwoFactorSetupView(views.APIView):
    """Setup 2FA for the current user"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TwoFactorSetupSerializer

    def post(self, request):
        """Setup 2FA and return QR code"""
        try:
            result = TwoFactorAuthService.setup_2fa(request.user)
            serializer = TwoFactorSetupSerializer(result)
            return Response(serializer.data)
        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    tags=["Two-Factor Authentication"],
    summary="Verify 2FA setup",
    description="Verify the 2FA setup with a token to confirm the device.",
    request=TwoFactorVerifySerializer,
    responses={200: TwoFactorBackupCodesSerializer}
)
class TwoFactorVerifySetupView(views.APIView):
    """Verify 2FA setup with token"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """Verify 2FA setup token"""
        serializer = TwoFactorVerifySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Refresh user from database to get updated relationships
        request.user.refresh_from_db()

        result = TwoFactorAuthService.verify_2fa_setup(request.user, serializer.validated_data['token'])

        if result['success']:
            response_serializer = TwoFactorBackupCodesSerializer({'backup_codes': result['backup_codes']})
            return Response(response_serializer.data)
        else:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    tags=["Two-Factor Authentication"],
    summary="Verify 2FA login",
    description="Verify a 2FA token during login process.",
    request=TwoFactorVerifyLoginSerializer,
    responses={200: OpenApiTypes.OBJECT}
)
class TwoFactorVerifyLoginView(views.APIView):
    """Verify 2FA token during login"""
    permission_classes = [permissions.IsAuthenticated]  # User must be authenticated

    def post(self, request):
        """Verify 2FA token for login"""
        serializer = TwoFactorVerifyLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data.get('token')
        backup_code = serializer.validated_data.get('backup_code')

        # Try token first, then backup code
        if token and TwoFactorAuthService.verify_2fa_token(request.user, token):
            # Generate JWT tokens for successful 2FA verification
            from rest_framework_simplejwt.tokens import RefreshToken

            refresh = RefreshToken.for_user(request.user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            return Response({
                'verified': True,
                'method': 'token',
                'access': access_token,
                'refresh': refresh_token,
                'user': {
                    'id': request.user.id,
                    'email': request.user.email,
                    'first_name': request.user.first_name,
                    'last_name': request.user.last_name,
                }
            })
        elif backup_code and request.user.verify_backup_code(backup_code):
            # Generate JWT tokens for successful backup code verification
            from rest_framework_simplejwt.tokens import RefreshToken

            refresh = RefreshToken.for_user(request.user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            return Response({
                'verified': True,
                'method': 'backup_code',
                'access': access_token,
                'refresh': refresh_token,
                'user': {
                    'id': request.user.id,
                    'email': request.user.email,
                    'first_name': request.user.first_name,
                    'last_name': request.user.last_name,
                }
            })
        else:
            return Response({'error': 'Invalid token or backup code'}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    tags=["Two-Factor Authentication"],
    summary="Disable 2FA",
    description="Disable two-factor authentication for the current user.",
    responses={200: OpenApiTypes.OBJECT}
)
class TwoFactorDisableView(views.APIView):
    """Disable 2FA for the current user"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = None

    def post(self, request):
        """Disable 2FA"""
        try:
            TwoFactorAuthService.disable_2fa(request.user)
            return Response({'message': '2FA disabled successfully'})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    tags=["Two-Factor Authentication"],
    summary="Regenerate backup codes",
    description="Generate new backup codes for 2FA recovery.",
    responses={200: TwoFactorBackupCodesSerializer}
)
class TwoFactorRegenerateBackupCodesView(views.APIView):
    """Regenerate backup codes"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TwoFactorBackupCodesSerializer

    def post(self, request):
        """Regenerate backup codes"""
        try:
            backup_codes = TwoFactorAuthService.regenerate_backup_codes(request.user)
            serializer = TwoFactorBackupCodesSerializer({'backup_codes': backup_codes})
            return Response(serializer.data)
        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    tags=["Two-Factor Authentication"],
    summary="Get 2FA status",
    description="Get the current two-factor authentication status for the user.",
    responses={200: TwoFactorStatusSerializer}
)
class TwoFactorStatusView(views.APIView):
    """Get 2FA status for the current user"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Get 2FA status"""
        # Refresh user from database to get updated relationships
        request.user.refresh_from_db()
        
        status_data = TwoFactorAuthService.get_2fa_status(request.user)
        serializer = TwoFactorStatusSerializer(status_data)
        return Response(serializer.data)


# Email Confirmation Redirect View
class EmailConfirmationRedirectView(views.APIView):
    """
    Custom email confirmation view that processes the confirmation
    and redirects to the frontend.
    """
    permission_classes = []  # Allow unauthenticated access

    def get(self, request, key):
        """
        Handle email confirmation by processing the key and redirecting to frontend.
        """
        from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC
        from django.shortcuts import redirect
        from django.contrib import messages
        from django.conf import settings

        try:
            # Try HMAC confirmation first
            confirmation = EmailConfirmationHMAC.from_key(key)
            if confirmation:
                confirmation.confirm(request)
                # Success - redirect to frontend with success
                frontend_url = f"{settings.FRONTEND_URL}/auth/confirm-email?status=success&email={confirmation.email_address.email}"
                return redirect(frontend_url)
        except Exception as e:
            pass

        try:
            # Try regular EmailConfirmation
            confirmation = EmailConfirmation.objects.get(key=key)
            confirmation.confirm(request)
            # Success - redirect to frontend with success
            frontend_url = f"{settings.FRONTEND_URL}/auth/confirm-email?status=success&email={confirmation.email_address.email}"
            return redirect(frontend_url)
        except EmailConfirmation.DoesNotExist:
            # Invalid key - redirect to frontend with error
            frontend_url = f"{settings.FRONTEND_URL}/auth/confirm-email?status=error&message=invalid_key"
            return redirect(frontend_url)
        except Exception as e:
            # Other error - redirect to frontend with error
            frontend_url = f"{settings.FRONTEND_URL}/auth/confirm-email?status=error&message={str(e)}"
            return redirect(frontend_url)