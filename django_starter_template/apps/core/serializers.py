"""
Custom serializers for core authentication endpoints
"""
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenRefreshSerializer, TokenBlacklistSerializer
from rest_framework_simplejwt.exceptions import InvalidToken
from django.contrib.admin.models import LogEntry
from django.contrib.contenttypes.models import ContentType
from drf_spectacular.utils import extend_schema_field
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.utils import timezone
from allauth.socialaccount.models import SocialAccount
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.serializers import LoginSerializer, PasswordChangeSerializer
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()

# Authentication Serializers
class CustomRegisterSerializer(RegisterSerializer):
    """Custom registration serializer for dj-rest-auth"""
    first_name = serializers.CharField(required=True, max_length=150)
    last_name = serializers.CharField(required=True, max_length=150)
    phone_number = serializers.CharField(required=False, max_length=15, allow_blank=True)
    employee_id = serializers.CharField(required=False, max_length=50, allow_blank=True)
    department = serializers.CharField(required=False, max_length=100, allow_blank=True)
    role = serializers.CharField(required=False, max_length=50, allow_blank=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove username field since we use email as USERNAME_FIELD
        if 'username' in self.fields:
            del self.fields['username']

        # Make passwords optional - they'll be auto-generated if not provided
        self.fields['password1'].required = False
        self.fields['password1'].help_text = "Optional. If not provided, a random password will be set."
        self.fields['password2'].required = False
        self.fields['password2'].help_text = "Optional. If not provided, a random password will be set."

    def validate(self, data):
        # Auto-generate password if not provided
        if not data.get('password1'):
            import random
            import string
            random_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            self.initial_data['password1'] = random_password
            self.initial_data['password2'] = random_password

        self.cleaned_data = {}
    
    def validate_email(self, email):
        """Custom email validation to provide better error messages"""
        email = super().validate_email(email)
        site_name = settings.SITE_NAME
        if site_name:
            # Check for protected system emails
            if email == f'anonymous@{site_name}.system':
                raise serializers.ValidationError(
                    "This email address is reserved for system use and cannot be registered."
                )
        
        # Check if email already exists
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                "A user with this email address already exists."
            )
        
        return email
    
    def get_cleaned_data(self):
        data = super().get_cleaned_data()
        data.update({
            'first_name': self.validated_data.get('first_name', ''),
            'last_name': self.validated_data.get('last_name', ''),
            'phone_number': self.validated_data.get('phone_number', ''),
            'employee_id': self.validated_data.get('employee_id', ''),
            'department': self.validated_data.get('department', ''),
            'role': self.validated_data.get('role', ''),
        })
        return data

    def save(self, request):
        user = super().save(request)

        # Set additional fields on user
        user.first_name = self.validated_data.get('first_name', '')
        user.last_name = self.validated_data.get('last_name', '')
        user.employee_id = self.validated_data.get('employee_id', '')

        # Set role if provided
        role_name = self.validated_data.get('role')
        if role_name:
            try:
                from apps.accounts.models import UserRole
                role, created = UserRole.objects.get_or_create(name=role_name)
                user.role = role
            except Exception as e:
                # Log error but don't fail registration
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Could not set role {role_name} for user {user.email}: {str(e)}")

        user.save()

        # Create or update user profile with additional fields
        from apps.accounts.models import UserProfile
        profile, created = UserProfile.objects.get_or_create(user=user)
        profile.phone_number = self.validated_data.get('phone_number', '')
        profile.department = self.validated_data.get('department', '')
        profile.save()

        return user


class CustomLoginSerializer(LoginSerializer):
    """Custom login serializer that uses email instead of username."""
    username = None
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        if email and password:
            # Check if user exists and is approved (for staff)
            try:
                user = User.objects.get(email=email)
                if user.is_staff and not user.is_approved:
                    raise serializers.ValidationError(
                        'Your account is pending approval. Please contact your administrator.'
                    )
                if user.account_locked_until and user.account_locked_until > timezone.now():
                    raise serializers.ValidationError(
                        'Your account is temporarily locked. Please try again later.'
                    )
                if user and user.check_password(password):
                    attrs['user'] = user
                    return attrs
                else:
                    raise serializers.ValidationError('Unable to log in with provided credentials.')
            except User.DoesNotExist:
                pass
        else:
            raise serializers.ValidationError('Must include "email" and "password".')
        
        return super().validate(attrs)


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    """
    Custom token refresh serializer that reads refresh token from cookies
    instead of request body, since frontend cannot access httpOnly cookies.
    """
    refresh = serializers.CharField(required=False, write_only=True)

    def validate(self, attrs):
        # Get refresh token from cookies if not provided in request body
        request = self.context.get('request')
        if not request:
            raise InvalidToken('No request context available.')

        refresh_token = attrs.get('refresh') or request.COOKIES.get('refresh')
        if not refresh_token:
            raise InvalidToken('No refresh token found in request body or cookies.')

        # Set the refresh token for parent validation
        attrs['refresh'] = refresh_token

        try:
            return super().validate(attrs)
        except Exception as e:
            error_msg = str(e)
            if 'User matching query does not exist' in error_msg:
                raise InvalidToken('Token contains invalid user.')
            elif 'Token is invalid or expired' in error_msg:
                raise InvalidToken('Token is invalid or expired.')
            elif 'Signature has expired' in error_msg:
                raise InvalidToken('Token has expired.')
            else:
                # Re-raise the original exception for other errors
                raise

class CustomLogoutSerializer(TokenBlacklistSerializer):
    """
    Custom logout serializer that reads refresh token from cookies
    instead of request body, since frontend cannot access httpOnly cookies.
    """
    refresh = serializers.CharField(required=False, write_only=True)

    def validate(self, attrs):
        # Get refresh token from cookies if not provided in request body
        request = self.context.get('request')
        if not request:
            raise InvalidToken('No request context available.')

        refresh_token = attrs.get('refresh') or request.COOKIES.get('refresh')
        if not refresh_token:
            raise InvalidToken('No refresh token found in request body or cookies.')

        # Set the refresh token for parent validation
        attrs['refresh'] = refresh_token

        try:
            return super().validate(attrs)
        except Exception as e:
            error_msg = str(e)
            if 'User matching query does not exist' in error_msg:
                raise InvalidToken('Token contains invalid user.')
            elif 'Token is invalid or expired' in error_msg:
                raise InvalidToken('Token is invalid or expired.')
            elif 'Signature has expired' in error_msg:
                raise InvalidToken('Token has expired.')
            else:
                # Re-raise the original exception for other errors
                raise


class CustomPasswordChangeSerializer(PasswordChangeSerializer):
    """Custom password change serializer"""
    
    def save(self):
        user = super().save()
        # user.password_changed_at = timezone.now()
        # user.must_change_password = False
        # user.save(update_fields=['password_changed_at', 'must_change_password'])
        return user

 
class PasswordResetSerializer(serializers.Serializer):
    """
    Custom password reset serializer
    """
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Enhanced password reset confirm serializer with better API documentation
    """
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password1 = serializers.CharField()
    new_password2 = serializers.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add help text and better field descriptions for API documentation
        self.fields['uid'].help_text = 'User ID encoded in base36 format from the password reset email'
        self.fields['token'].help_text = 'Password reset token from the password reset email'
        self.fields['new_password1'].help_text = 'New password (minimum 8 characters)'
        self.fields['new_password2'].help_text = 'Confirm new password (must match new_password1)'

        # Set labels for better API documentation
        self.fields['uid'].label = 'User ID'
        self.fields['token'].label = 'Reset Token'
        self.fields['new_password1'].label = 'New Password'
        self.fields['new_password2'].label = 'Confirm Password'


class PasswordResetConfirmResponseSerializer(serializers.Serializer):
    """
    Response serializer for password reset confirmation
    """
    detail = serializers.CharField(
        default="Password has been reset with the new password.",
        help_text="Success message confirming password reset"
    )


# Two-Factor Authentication Serializers
class TwoFactorSetupSerializer(serializers.Serializer):
    """Serializer for 2FA setup response"""
    device_id = serializers.IntegerField(read_only=True)
    provisioning_uri = serializers.CharField(read_only=True)
    qr_code = serializers.CharField(read_only=True)
    secret = serializers.CharField(read_only=True)


class TwoFactorVerifySerializer(serializers.Serializer):
    """Serializer for 2FA verification during setup"""
    token = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate_token(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Token must contain only digits")
        return value


class TwoFactorVerifyLoginSerializer(serializers.Serializer):
    """Serializer for 2FA verification during login"""
    token = serializers.CharField(max_length=6, min_length=6, required=True)
    backup_code = serializers.CharField(max_length=8, min_length=8, required=False)

    def validate_token(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Token must contain only digits")
        return value

    def validate_backup_code(self, value):
        if value and not value.replace('-', '').isalnum():
            raise serializers.ValidationError("Backup code format is invalid")
        return value


class TwoFactorStatusSerializer(serializers.Serializer):
    """Serializer for 2FA status response"""
    enabled = serializers.BooleanField(read_only=True)
    confirmed = serializers.BooleanField(read_only=True)
    backup_codes_count = serializers.IntegerField(read_only=True)
    device_name = serializers.CharField(read_only=True)


class TwoFactorBackupCodesSerializer(serializers.Serializer):
    """Serializer for backup codes response"""
    backup_codes = serializers.ListField(
        child=serializers.CharField(max_length=8),
        read_only=True
    )

class LogEntrySerializer(serializers.ModelSerializer):
    content_type = serializers.SerializerMethodField()
    user = serializers.SerializerMethodField()

    class Meta:
        model = LogEntry
        fields = [
            'id', 'action_flag', 'change_message', 'object_id', 'object_repr',
            'content_type', 'user', 'action_time'
        ]

    @extend_schema_field(serializers.CharField())
    def get_content_type(self, obj):
        return ContentType.objects.get_for_id(obj.content_type_id).model

    @extend_schema_field(serializers.CharField(allow_null=True))
    def get_user(self, obj):
        return obj.user.get_username() if obj.user else None