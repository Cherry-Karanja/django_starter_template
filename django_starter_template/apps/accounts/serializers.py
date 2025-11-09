"""
Serializers for accounts app with separate serializers for different operations
"""
from typing import Optional, Dict, Any
from rest_framework import serializers
from django.contrib.auth.models import Permission
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.utils import timezone
from allauth.socialaccount.models import SocialAccount
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.serializers import LoginSerializer, PasswordChangeSerializer, JWTSerializer
from drf_spectacular.utils import extend_schema_field
from .models import User, UserProfile, UserRole, UserRoleHistory, UserSession, LoginAttempt
from .services import UserService, RoleService


class PermissionSerializer(serializers.ModelSerializer):
    """Permission serializer"""
    app_label = serializers.CharField(source='content_type.app_label', read_only=True)
    model = serializers.CharField(source='content_type.model', read_only=True)

    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename', 'app_label', 'model']


# User Role Serializers
class UserRoleListSerializer(serializers.ModelSerializer):
    """User role serializer for list views"""
    permissions_count = serializers.SerializerMethodField()
    users_count = serializers.SerializerMethodField()
    display_name = serializers.CharField(source='get_name_display', read_only=True)

    class Meta:
        model = UserRole
        fields = ['id', 'name', 'display_name', 'description', 'is_active', 'permissions_count', 'users_count', 'created_at']

    @extend_schema_field(serializers.IntegerField)
    def get_permissions_count(self, obj) -> int:
        return obj.permissions.count()

    @extend_schema_field(serializers.IntegerField)
    def get_users_count(self, obj) -> int:
        return obj.users.count()


class UserRoleDetailSerializer(serializers.ModelSerializer):
    """User role serializer for detail views"""
    permissions = PermissionSerializer(many=True, read_only=True)
    permissions_count = serializers.SerializerMethodField()
    users_count = serializers.SerializerMethodField()
    display_name = serializers.CharField(source='get_name_display', read_only=True)

    class Meta:
        model = UserRole
        fields = ['id', 'name', 'display_name', 'description', 'permissions', 'permissions_count', 'users_count', 'is_active', 'created_at']

    @extend_schema_field(serializers.IntegerField)
    def get_permissions_count(self, obj) -> int:
        return obj.permissions.count()

    @extend_schema_field(serializers.IntegerField)
    def get_users_count(self, obj) -> int:
        return obj.users.count()


class UserRoleCreateSerializer(serializers.ModelSerializer):
    """User role serializer for create operations"""
    permissions = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        write_only=True,
        help_text="List of permission codenames to assign to this role"
    )

    class Meta:
        model = UserRole
        fields = ['name', 'description', 'permissions', 'is_active']

    def create(self, validated_data):
        permissions = validated_data.pop('permissions', [])
        role = super().create(validated_data)
        if permissions:
            RoleService.update_role_permissions(role, permissions)
        return role


class UserRoleUpdateSerializer(serializers.ModelSerializer):
    """User role serializer for update operations"""
    permissions = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        write_only=True,
        help_text="List of permission codenames to assign to this role"
    )

    class Meta:
        model = UserRole
        fields = ['name', 'description', 'permissions', 'is_active']

    def update(self, instance, validated_data):
        permissions = validated_data.pop('permissions', None)
        role = super().update(instance, validated_data)
        if permissions is not None:
            RoleService.update_role_permissions(role, permissions)
        return role


# User Serializers
class UserListSerializer(serializers.ModelSerializer):
    """User serializer for list views"""
    role_display = serializers.CharField(source='role.display_name', read_only=True)
    full_name = serializers.SerializerMethodField()
    location = serializers.SerializerMethodField()
    is_staff_member = serializers.SerializerMethodField()
    department = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            'id', 'email', 'first_name', 'last_name', 'username', 'full_name',
            'department', 'role_display', 'is_active', 'is_approved', 'is_verified',
            'is_staff', 'location', 'is_staff_member',
            'date_joined', 'last_login', 'created_at'
        )

    @extend_schema_field(serializers.CharField)
    def get_full_name(self, obj) -> str:
        return obj.get_full_name()

    @extend_schema_field(serializers.CharField)
    def get_location(self, obj) -> str:
        return ''  # Not implemented

    @extend_schema_field(serializers.BooleanField)
    def get_is_staff_member(self, obj) -> bool:
        return obj.is_staff

    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_department(self, obj: User) -> str:
        """Get department from user profile"""
        try:
            return obj.profile.department
        except UserProfile.DoesNotExist:
            return ''


class UserDetailSerializer(serializers.ModelSerializer):
    """User serializer for detail views"""
    role_display = serializers.CharField(source='role.display_name', read_only=True)
    full_name = serializers.SerializerMethodField()
    location = serializers.SerializerMethodField()
    profile = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()
    role_permissions = serializers.SerializerMethodField()
    phone_number = serializers.SerializerMethodField()
    department = serializers.SerializerMethodField()
    date_of_birth = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()
    ward = serializers.SerializerMethodField()
    constituency = serializers.SerializerMethodField()
    county = serializers.SerializerMethodField()
    last_login_ip = serializers.CharField(read_only=True, required=False)

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name', 'phone_number',
            'employee_id', 'department', 'date_of_birth', 'profile_picture',
            'ward', 'constituency', 'county', 'location', 'role_display',
            'is_active', 'is_approved', 'is_verified', 'is_staff',
            'failed_login_attempts', 'account_locked_until', 'last_login_ip',
            'profile', 'permissions', 'role_permissions',
            'date_joined', 'last_login', 'created_at', 'updated_at'
        ]

    @extend_schema_field(serializers.CharField)
    def get_full_name(self, obj) -> str:
        return obj.get_full_name()

    @extend_schema_field(serializers.CharField)
    def get_location(self, obj) -> str:
        return ''  # Not implemented

    @extend_schema_field(serializers.DictField)
    def get_profile(self, obj) -> Optional[Dict[str, Any]]:
        if hasattr(obj, 'profile'):
            return UserProfileListSerializer(obj.profile).data
        return None

    @extend_schema_field(serializers.ListField)
    def get_permissions(self, obj) -> list:
        # This would be implemented to show effective permissions
        return []

    @extend_schema_field(serializers.ListField)
    def get_role_permissions(self, obj) -> list:
        if obj.role:
            return list(obj.role.permissions.values_list('codename', flat=True))
        return []

    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_phone_number(self, obj: User) -> str:
        """Get phone number from user profile"""
        try:
            return obj.profile.phone_number
        except UserProfile.DoesNotExist:
            return ''
    
    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_department(self, obj: User) -> str:
        """Get department from user profile"""
        try:
            return obj.profile.department
        except UserProfile.DoesNotExist:
            return ''
    
    @extend_schema_field(serializers.DateField(allow_null=True))
    def get_date_of_birth(self, obj: User) -> Optional[str]:
        """Get date of birth (not implemented yet)"""
        return None
    
    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_profile_picture(self, obj: User) -> str:
        """Get profile picture (not implemented yet)"""
        return ''
    
    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_ward(self, obj: User) -> str:
        """Get ward (not implemented yet)"""
        return ''
    
    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_constituency(self, obj: User) -> str:
        """Get constituency (not implemented yet)"""
        return ''
    
    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_county(self, obj: User) -> str:
        """Get county (not implemented yet)"""
        return ''


class UserCreateSerializer(serializers.ModelSerializer):
    """User serializer for create operations"""
    password = serializers.CharField(write_only=True, required=True)
    role_name = serializers.CharField(write_only=True, required=False)
    phone_number = serializers.CharField(write_only=True, required=False, allow_blank=True)
    department = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = User
        fields = [
            'email', 'password', 'first_name', 'last_name', 'phone_number',
            'employee_id', 'department', 'role_name', 'is_active', 'is_approved', 'is_verified'
        ]

    def create(self, validated_data):
        role_name = validated_data.pop('role_name', None)
        password = validated_data.pop('password')
        phone_number = validated_data.pop('phone_number', '')
        department = validated_data.pop('department', '')

        if role_name:
            user = UserService.create_user_with_role(
                email=validated_data['email'],
                password=password,
                first_name=validated_data['first_name'],
                last_name=validated_data['last_name'],
                role_name=role_name,
                **validated_data
            )
        else:
            user = User.objects.create_user(
                email=validated_data['email'],
                password=password,
                **validated_data
            )

        # Create or update user profile
        from .models import UserProfile
        profile, created = UserProfile.objects.get_or_create(user=user)
        if phone_number:
            profile.phone_number = phone_number
        if department:
            profile.department = department
        profile.save()

        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """User serializer for update operations"""
    role_name = serializers.CharField(write_only=True, required=False)
    phone_number = serializers.CharField(required=False, allow_blank=True)
    employee_id = serializers.CharField(required=False, allow_blank=True)
    department = serializers.CharField(required=False, allow_blank=True)
    date_of_birth = serializers.DateField(required=False, allow_null=True)
    ward = serializers.CharField(required=False, allow_blank=True)
    constituency = serializers.CharField(required=False, allow_blank=True)
    county = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'phone_number', 'employee_id', 'department',
            'date_of_birth', 'ward', 'constituency', 'county', 'role_name',
            'is_active', 'is_approved', 'is_verified'
        ]

    def update(self, instance, validated_data):
        role_name = validated_data.pop('role_name', None)
        
        # Handle profile fields
        profile_fields = ['phone_number', 'employee_id', 'department', 'date_of_birth', 'ward', 'constituency', 'county']
        profile_data = {}
        for field in profile_fields:
            if field in validated_data:
                profile_data[field] = validated_data.pop(field)
        
        user = super().update(instance, validated_data)

        # Update profile if needed
        if profile_data:
            profile, created = UserProfile.objects.get_or_create(user=user)
            for field, value in profile_data.items():
                if value is not None:
                    setattr(profile, field, value)
            profile.save()

        if role_name and (not user.role or user.role.name != role_name):
            user = UserService.update_user_role(
                user=user,
                new_role_name=role_name,
                changed_by=self.context['request'].user
            )

        return user


# User Profile Serializers
class UserProfileListSerializer(serializers.ModelSerializer):
    """User profile serializer for list views"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = [
            'id', 'user_email', 'user_name', 'preferred_language',
            'show_email', 'show_phone', 'allow_notifications', 'created_at', 'updated_at'
        ]

    @extend_schema_field(serializers.CharField)
    def get_user_name(self, obj) -> str:
        return obj.user.get_full_name()


class UserProfileDetailSerializer(serializers.ModelSerializer):
    """User profile serializer for detail views"""
    user = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = [
            'id', 'user', 'bio', 'preferred_language',
            'show_email', 'show_phone', 'allow_notifications',
            'interface_theme', 'created_at', 'updated_at'
        ]

    @extend_schema_field(serializers.DictField)
    def get_user(self, obj) -> Dict[str, Any]:
        return {
            'id': obj.user.id,
            'email': obj.user.email,
            'full_name': obj.user.get_full_name(),
            'role': obj.user.role.display_name if obj.user.role else None
        }


class UserProfileCreateSerializer(serializers.ModelSerializer):
    """User profile serializer for create operations"""

    class Meta:
        model = UserProfile
        fields = [
            'bio', 'preferred_language', 'show_email',
            'show_phone', 'allow_notifications', 'interface_theme'
        ]


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """User profile serializer for update operations"""

    class Meta:
        model = UserProfile
        fields = [
            'bio', 'preferred_language', 'show_email',
            'show_phone', 'allow_notifications', 'interface_theme'
        ]


# User Role History Serializer
class UserRoleHistorySerializer(serializers.ModelSerializer):
    """User role history serializer"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()
    old_role_display = serializers.CharField(source='old_role.get_name_display', read_only=True)
    new_role_display = serializers.CharField(source='new_role.get_name_display', read_only=True)
    changed_by_email = serializers.CharField(source='changed_by.email', read_only=True)
    changed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = UserRoleHistory
        fields = [
            'id', 'user_email', 'user_name', 'old_role_display', 'new_role_display',
            'reason', 'changed_by_email', 'changed_by_name', 'created_at'
        ]

    @extend_schema_field(serializers.CharField)
    def get_user_name(self, obj) -> str:
        return obj.user.get_full_name()

    @extend_schema_field(serializers.CharField)
    def get_changed_by_name(self, obj) -> str:
        return obj.changed_by.get_full_name() if obj.changed_by else ''


# User Session Serializer
class UserSessionSerializer(serializers.ModelSerializer):
    """User session serializer"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()
    duration = serializers.SerializerMethodField()
    ip_address = serializers.CharField(read_only=True)

    class Meta:
        model = UserSession
        fields = [
            'id', 'user_email', 'user_name', 'ip_address', 'user_agent',
            'is_active', 'created_at', 'last_activity', 'duration'
        ]

    @extend_schema_field(serializers.CharField)
    def get_user_name(self, obj) -> str:
        return obj.user.get_full_name()

    @extend_schema_field(serializers.DurationField)
    def get_duration(self, obj) -> Optional[str]:
        if obj.last_activity and obj.created_at:
            return str(obj.last_activity - obj.created_at)
        return None


# Login Attempt Serializer
class LoginAttemptSerializer(serializers.ModelSerializer):
    """Login attempt serializer"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()
    ip_address = serializers.CharField(read_only=True)

    class Meta:
        model = LoginAttempt
        fields = ['id', 'user_email', 'user_name', 'ip_address', 'user_agent', 'success', 'created_at']

    @extend_schema_field(serializers.CharField)
    def get_user_name(self, obj) -> str:
        return obj.user.get_full_name() if obj.user else ''


# Management Serializers (for admin operations)
class UserManagementSerializer(UserDetailSerializer):
    """User management serializer for admin operations"""
    pass


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
        
        # Check for protected system emails
        if email == 'anonymous@agex.system':
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
                from .models import UserRole
                role, created = UserRole.objects.get_or_create(name=role_name)
                user.role = role
            except Exception as e:
                # Log error but don't fail registration
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Could not set role {role_name} for user {user.email}: {str(e)}")

        user.save()

        # Create or update user profile with additional fields
        from .models import UserProfile
        profile, created = UserProfile.objects.get_or_create(user=user)
        profile.phone_number = self.validated_data.get('phone_number', '')
        profile.department = self.validated_data.get('department', '')
        profile.save()

        return user


# API Response Serializers
class UserPermissionsSerializer(serializers.Serializer):
    """User permissions response serializer"""
    user_id = serializers.IntegerField()
    role = serializers.CharField(allow_null=True)
    permissions = serializers.ListField(child=serializers.CharField())
    is_staff = serializers.BooleanField()
    is_supervisor = serializers.BooleanField()
    is_admin = serializers.BooleanField()


class UserRoleChangeRequestSerializer(serializers.Serializer):
    """User role change request serializer"""
    role_name = serializers.CharField(max_length=50)


class UserRoleChangeResponseSerializer(serializers.Serializer):
    """User role change response serializer"""
    message = serializers.CharField()
    user = UserDetailSerializer()


class UserApprovalSerializer(serializers.Serializer):
    """User approval response serializer"""
    message = serializers.CharField()


class SocialAuthURLSerializer(serializers.Serializer):
    """Social authentication URLs serializer"""
    google = serializers.URLField(allow_null=True)
    github = serializers.URLField(allow_null=True)
    facebook = serializers.URLField(allow_null=True)



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


class UserDetailsSerializer(serializers.ModelSerializer):
    """User details serializer for dj-rest-auth"""
    role = UserRoleDetailSerializer(read_only=True)
    full_name = serializers.SerializerMethodField()
    profile = serializers.SerializerMethodField()
    phone_number = serializers.SerializerMethodField()
    department = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'phone_number', 'employee_id', 'department',
            'role', 'is_verified', 'is_approved',
            'created_at', 'last_login', 'profile'
        ]
        read_only_fields = [
            'id', 'email', 'is_verified', 'is_approved',
            'created_at', 'last_login'
        ]
    
    @extend_schema_field(serializers.CharField)
    def get_full_name(self, obj: User) -> str:
        """Get user's full name"""
        return obj.get_full_name()
    
    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_phone_number(self, obj: User) -> str:
        """Get phone number from user profile"""
        try:
            return obj.profile.phone_number
        except UserProfile.DoesNotExist:
            return ''
    
    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_department(self, obj: User) -> str:
        """Get department from user profile"""
        try:
            return obj.profile.department
        except UserProfile.DoesNotExist:
            return ''
    
    @extend_schema_field(serializers.DictField(allow_null=True))
    def get_profile(self, obj: User) -> Optional[Dict[str, Any]]:
        """Get user profile details"""
        try:
            profile = obj.profile
            return {
                'bio': profile.bio,
                'preferred_language': profile.preferred_language
            }
        except UserProfile.DoesNotExist:
            return None


class CustomPasswordChangeSerializer(PasswordChangeSerializer):
    """Custom password change serializer"""
    
    def save(self):
        user = super().save()
        # user.password_changed_at = timezone.now()
        # user.must_change_password = False
        # user.save(update_fields=['password_changed_at', 'must_change_password'])
        return user


class CustomJWTSerializer(JWTSerializer):
    """Custom JWT serializer to include user role information"""
    user = UserDetailsSerializer(read_only=True)


class UserManagementSerializer(serializers.ModelSerializer):
    """Serializer for user management by admins"""
    role_name = serializers.CharField(write_only=True, required=False)
    role = UserRoleListSerializer(read_only=True, allow_null=True)
    full_name = serializers.ReadOnlyField()
    employee_id = serializers.SerializerMethodField()
    department = serializers.SerializerMethodField()
    phone_number = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'employee_id', 'department', 'phone_number',
            'role', 'role_name', 'is_active', 'is_approved', 'is_verified',
            'created_at', 'date_joined', 'last_login', 'failed_login_attempts',
            'account_locked_until', 'password_changed_at', 'must_change_password'
        ]
        read_only_fields = ['id', 'email', 'created_at', 'last_login', 'failed_login_attempts',
                           'account_locked_until', 'password_changed_at']
    
    def update(self, instance, validated_data):
        role_name = validated_data.pop('role_name', None)
        
        if role_name:
            try:
                new_role = UserRole.objects.get(name=role_name)
                instance.role = new_role
            except UserRole.DoesNotExist:
                raise serializers.ValidationError(f"Role '{role_name}' does not exist")
        
        return super().update(instance, validated_data)

    def get_employee_id(self, obj):
        return obj.employee_id

    def get_department(self, obj):
        try:
            return obj.profile.department
        except UserProfile.DoesNotExist:
            return ''

    def get_phone_number(self, obj):
        try:
            return obj.profile.phone_number
        except UserProfile.DoesNotExist:
            return ''


# Social Authentication Serializers
class SocialAuthURLSerializer(serializers.Serializer):
    """Serializer for social authentication URLs response"""
    google = serializers.URLField()
    github = serializers.URLField()
    facebook = serializers.URLField()


# API Response Serializers
class UserApprovalSerializer(serializers.Serializer):
    """Serializer for user approval response"""
    message = serializers.CharField()


class UserRoleChangeRequestSerializer(serializers.Serializer):
    """Serializer for role change request"""
    role_name = serializers.CharField(help_text="Name of the role to assign")


class UserRoleChangeResponseSerializer(serializers.Serializer):
    """Serializer for role change response"""
    message = serializers.CharField()
    user = UserManagementSerializer()


class UserPermissionsSerializer(serializers.Serializer):
    """Serializer for user permissions response"""
    id = serializers.IntegerField()
    role = serializers.CharField(allow_null=True)
    permissions = serializers.ListField(child=serializers.CharField())
    is_staff = serializers.BooleanField()
    is_supervisor = serializers.BooleanField()
    is_admin = serializers.BooleanField()


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile management"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.full_name', read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            'id', 'user', 'user_email', 'user_full_name', 'bio', 'preferred_language',
            'show_email', 'show_phone', 'allow_notifications',
            'interface_theme', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class UserRoleHistorySerializer(serializers.ModelSerializer):
    """Serializer for user role history"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.full_name', read_only=True)
    old_role_name = serializers.CharField(source='old_role.name', read_only=True)
    old_role_display = serializers.CharField(source='old_role.get_name_display', read_only=True)
    new_role_name = serializers.CharField(source='new_role.name', read_only=True)
    new_role_display = serializers.CharField(source='new_role.get_name_display', read_only=True)
    changed_by_email = serializers.CharField(source='changed_by.email', read_only=True)
    changed_by_name = serializers.CharField(source='changed_by.full_name', read_only=True)
    
    class Meta:
        model = UserRoleHistory
        fields = [
            'id', 'user', 'user_email', 'user_full_name', 'old_role', 'old_role_name',
            'old_role_display', 'new_role', 'new_role_name', 'new_role_display',
            'changed_by', 'changed_by_email', 'changed_by_name', 'reason',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer for user session management"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_full_name = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()
    risk_score = serializers.SerializerMethodField()
    ip_address = serializers.CharField(read_only=True)
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'user', 'user_email', 'user_full_name', 'session_key', 'ip_address',
            'user_agent', 'is_active', 'expires_at', 'device_type', 'device_os',
            'browser', 'location_info', 'last_activity', 'is_expired', 'risk_score', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_user_full_name(self, obj):
        return obj.user.get_full_name()

    @extend_schema_field(serializers.CharField)
    def get_is_expired(self, obj) -> bool:
        return obj.is_expired

    @extend_schema_field(serializers.FloatField)
    def get_risk_score(self, obj) -> float:
        return obj.risk_score
class LoginAttemptSerializer(serializers.ModelSerializer):
    """Serializer for login attempt tracking"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.full_name', read_only=True)
    ip_address = serializers.CharField(read_only=True)
    
    class Meta:
        model = LoginAttempt
        fields = [
            'id', 'user', 'user_email', 'user_full_name', 'email', 'ip_address',
            'success', 'user_agent', 'failure_reason', 'location_info', 'device_type',
            'device_os', 'browser', 'session_id', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class PermissionDetailSerializer(serializers.ModelSerializer):
    """Enhanced permission serializer for entity manager"""
    app_label = serializers.CharField(source='content_type.app_label', read_only=True)
    model = serializers.CharField(source='content_type.model', read_only=True)
    content_type_name = serializers.CharField(source='content_type.name', read_only=True)
    
    class Meta:
        model = Permission
        fields = [
            'id', 'name', 'codename', 'app_label', 'model', 'content_type_name'
        ]
        read_only_fields = ['id']