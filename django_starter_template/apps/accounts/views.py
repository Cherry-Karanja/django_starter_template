"""
Views for the accounts app
"""
from rest_framework import status, generics, permissions, filters, viewsets, views
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.utils import timezone
import logging
from dj_rest_auth.registration.views import RegisterView
from dj_rest_auth.views import LoginView
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiResponse
from drf_spectacular.types import OpenApiTypes
from apps.core.utils import get_client_ip
from .models import User, UserSession, LoginAttempt, UserRole, UserProfile, UserRoleHistory
from .serializers import (
    CustomRegisterSerializer, CustomLoginSerializer,
    UserListSerializer, UserDetailSerializer, UserCreateSerializer, UserUpdateSerializer,
    UserRoleListSerializer, UserRoleDetailSerializer, UserRoleCreateSerializer, UserRoleUpdateSerializer,
    UserProfileListSerializer, UserProfileDetailSerializer, UserProfileCreateSerializer, UserProfileUpdateSerializer,
    UserRoleHistorySerializer, UserSessionSerializer, LoginAttemptSerializer,
    UserPermissionsSerializer, UserRoleChangeRequestSerializer, UserRoleChangeResponseSerializer,
    UserApprovalSerializer, PermissionSerializer, PermissionCreateSerializer, PermissionUpdateSerializer, PermissionListSerializer,
    UserPermissionUpdateSerializer, UserPermissionResponseSerializer,
    TwoFactorSetupSerializer, TwoFactorVerifySerializer, TwoFactorVerifyLoginSerializer,
    TwoFactorStatusSerializer, TwoFactorBackupCodesSerializer
)
from apps.core.permissions import IsAdminOrReadOnly, IsOwnerOrStaff
from .constants import APIConstants
from .services import UserService, AuthenticationService, RoleService, TwoFactorAuthService

User = get_user_model()
logger = logging.getLogger(__name__)


@extend_schema(
    tags=["Authentication"],
    summary="Custom user registration",
    description="Register a new user with custom fields.",
    request=CustomRegisterSerializer,
    responses={201: CustomRegisterSerializer, 400: OpenApiResponse(description="Validation error")}
)
class CustomRegisterView(RegisterView):
    """Custom registration view"""
    serializer_class = CustomRegisterSerializer


@extend_schema(
    tags=["Authentication"],
    summary="Custom user login",
    description="Login with email and password.",
    request=CustomLoginSerializer,
    responses={200: OpenApiTypes.OBJECT, 400: OpenApiResponse(description="Invalid credentials")}
)
class CustomLoginView(LoginView):
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


@extend_schema_view(
    list=extend_schema(
        tags=["Users"],
        summary="List users",
        description="List all users with filtering and searching.",
        parameters=[
            OpenApiParameter(name="search", type=OpenApiTypes.STR, description="Search across email, name, employee_id"),
            OpenApiParameter(name="role_name", type=OpenApiTypes.STR, description="Filter by role name"),
            OpenApiParameter(name="is_active", type=OpenApiTypes.BOOL, description="Filter by active status"),
            OpenApiParameter(name="ordering", type=OpenApiTypes.STR, description=f"Order by: {', '.join(APIConstants.USER_ORDERING_FIELDS)}"),
        ]
    ),
    create=extend_schema(
        tags=["Users"],
        summary="Create user",
        description="Create a new user with role assignment."
    ),
    retrieve=extend_schema(
        tags=["Users"],
        summary="Retrieve user",
        description="Retrieve detailed information about a specific user."
    ),
    update=extend_schema(
        tags=["Users"],
        summary="Update user",
        description="Update a user's information including role changes."
    ),
    partial_update=extend_schema(
        tags=["Users"],
        summary="Partial update user",
        description="Partially update a user's information."
    ),
    destroy=extend_schema(
        tags=["Users"],
        summary="Delete user",
        description="Delete a user account."
    )
)
class UserViewSet(viewsets.ModelViewSet):
    """User management viewset"""
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = APIConstants.USER_SEARCH_FIELDS
    ordering_fields = APIConstants.USER_ORDERING_FIELDS
    ordering = ['-created_at']

    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'list':
            return UserListSerializer
        elif self.action == 'retrieve':
            return UserDetailSerializer
        elif self.action == 'create':
            return UserCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        return UserDetailSerializer

    def perform_create(self, serializer):
        """Create user and set current user for audit"""
        user = serializer.save()
        user._current_user = self.request.user

    def perform_update(self, serializer):
        """Update user and set current user for audit"""
        user = serializer.save()
        user._current_user = self.request.user

    def perform_destroy(self, instance):
        """Delete user and set current user for audit"""
        instance._current_user = self.request.user
        instance.delete()

    @extend_schema(
        summary="Approve user",
        description="Approve a user account for access.",
        request=None,
        responses={200: UserApprovalSerializer}
    )
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve a user account"""
        user = self.get_object()
        success = UserService.approve_user(user, request.user)
        if success:
            serializer = UserApprovalSerializer({'message': 'User approved successfully'})
            return Response(serializer.data)
        return Response({'error': 'Failed to approve user'}, status=400)

    @extend_schema(
        summary="Change user role",
        description="Change the role of a specific user.",
        request=UserRoleChangeRequestSerializer,
        responses={200: UserRoleChangeResponseSerializer}
    )
    @action(detail=True, methods=['post'])
    def change_role(self, request, pk=None):
        """Change user role"""
        user = self.get_object()
        role_name = request.data.get('role_name')

        if not role_name:
            return Response({'error': 'role_name is required'}, status=400)

        success = UserService.change_user_role(user, role_name, request.user)
        if success:
            serializer = UserRoleChangeResponseSerializer({
                'message': 'Role changed successfully',
                'user': UserDetailSerializer(user).data
            })
            return Response(serializer.data)
        return Response({'error': 'Failed to change role'}, status=400)

    @extend_schema(
        summary="Get user permissions",
        description="Get all permissions for the current user.",
        responses={200: UserPermissionsSerializer}
    )
    @action(detail=False, methods=['get'])
    def my_permissions(self, request):
        """Get current user's permissions"""
        permissions = UserService.get_user_permissions(request.user)
        serializer = UserPermissionsSerializer({
            'id': request.user.id,
            'role': request.user.role.name if request.user.role else None,
            'permissions': permissions,
            'is_staff': request.user.is_staff,
            'is_superuser': request.user.is_superuser
        })
        return Response(serializer.data)

    @extend_schema(
        summary="Update user permissions",
        description="Update the direct permissions assigned to a user (not through roles).",
        request=UserPermissionUpdateSerializer,
        responses={200: UserPermissionResponseSerializer}
    )
    @action(detail=True, methods=['post'])
    def update_permissions(self, request, pk=None):
        """Update user permissions"""
        user = self.get_object()
        serializer = UserPermissionUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        permission_codenames = serializer.validated_data['permissions']

        # Get current user permissions
        current_permissions = set(user.user_permissions.values_list('codename', flat=True))

        # Update permissions
        from django.contrib.auth.models import Permission
        new_permissions = Permission.objects.filter(codename__in=permission_codenames)
        user.user_permissions.set(new_permissions)

        # Calculate changes
        new_permission_codenames = set(permission_codenames)
        added_permissions = list(new_permission_codenames - current_permissions)
        removed_permissions = list(current_permissions - new_permission_codenames)

        response_serializer = UserPermissionResponseSerializer({
            'message': f'Permissions updated successfully. Added: {len(added_permissions)}, Removed: {len(removed_permissions)}',
            'user': UserDetailSerializer(user).data,
            'added_permissions': added_permissions,
            'removed_permissions': removed_permissions
        })

        return Response(response_serializer.data)

    @extend_schema(
        summary="Add permissions to user",
        description="Add specific permissions to a user without removing existing ones.",
        request=UserPermissionUpdateSerializer,
        responses={200: UserPermissionResponseSerializer}
    )
    @action(detail=True, methods=['post'])
    def add_permissions(self, request, pk=None):
        """Add permissions to user"""
        user = self.get_object()
        serializer = UserPermissionUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        permission_codenames = serializer.validated_data['permissions']

        # Get current user permissions
        current_permissions = set(user.user_permissions.values_list('codename', flat=True))

        # Add new permissions
        from django.contrib.auth.models import Permission
        new_permissions = Permission.objects.filter(codename__in=permission_codenames)
        user.user_permissions.add(*new_permissions)

        # Calculate changes
        added_permissions = [perm for perm in permission_codenames if perm not in current_permissions]

        response_serializer = UserPermissionResponseSerializer({
            'message': f'Permissions added successfully. Added: {len(added_permissions)}',
            'user': UserDetailSerializer(user).data,
            'added_permissions': added_permissions,
            'removed_permissions': []
        })

        return Response(response_serializer.data)

    @extend_schema(
        summary="Remove permissions from user",
        description="Remove specific permissions from a user.",
        request=UserPermissionUpdateSerializer,
        responses={200: UserPermissionResponseSerializer}
    )
    @action(detail=True, methods=['post'])
    def remove_permissions(self, request, pk=None):
        """Remove permissions from user"""
        user = self.get_object()
        serializer = UserPermissionUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        permission_codenames = serializer.validated_data['permissions']

        # Get current user permissions
        current_permissions = set(user.user_permissions.values_list('codename', flat=True))

        # Remove permissions
        from django.contrib.auth.models import Permission
        permissions_to_remove = Permission.objects.filter(codename__in=permission_codenames)
        user.user_permissions.remove(*permissions_to_remove)

        # Calculate changes
        removed_permissions = [perm for perm in permission_codenames if perm in current_permissions]

        response_serializer = UserPermissionResponseSerializer({
            'message': f'Permissions removed successfully. Removed: {len(removed_permissions)}',
            'user': UserDetailSerializer(user).data,
            'added_permissions': [],
            'removed_permissions': removed_permissions
        })

        return Response(response_serializer.data)


@extend_schema_view(
    list=extend_schema(
        tags=["Roles"],
        summary="List roles",
        description="List all roles with filtering and searching.",
        parameters=[
            OpenApiParameter(name="search", type=OpenApiTypes.STR, description="Search across name and description"),
            OpenApiParameter(name="is_active", type=OpenApiTypes.BOOL, description="Filter by active status"),
            OpenApiParameter(name="ordering", type=OpenApiTypes.STR, description=f"Order by: {', '.join(APIConstants.ROLE_ORDERING_FIELDS)}"),
        ]
    ),
    create=extend_schema(
        tags=["Roles"],
        summary="Create role",
        description="Create a new role with permissions."
    ),
    retrieve=extend_schema(
        tags=["Roles"],
        summary="Retrieve role",
        description="Retrieve detailed information about a specific role."
    ),
    update=extend_schema(
        tags=["Roles"],
        summary="Update role",
        description="Update a role's information and permissions."
    ),
    partial_update=extend_schema(
        tags=["Roles"],
        summary="Partial update role",
        description="Partially update a role's information."
    ),
    destroy=extend_schema(
        tags=["Roles"],
        summary="Delete role",
        description="Delete a role."
    )
)
class UserRoleViewSet(viewsets.ModelViewSet):
    """User role management viewset"""
    queryset = UserRole.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = APIConstants.ROLE_SEARCH_FIELDS
    ordering_fields = APIConstants.ROLE_ORDERING_FIELDS
    ordering = ['name']

    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'list':
            return UserRoleListSerializer
        elif self.action == 'retrieve':
            return UserRoleDetailSerializer
        elif self.action == 'create':
            return UserRoleCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return UserRoleUpdateSerializer
        return UserRoleDetailSerializer

    @extend_schema(
        summary="Get role users",
        description="Get all users with this role.",
        responses={200: UserListSerializer(many=True)}
    )
    @action(detail=True, methods=['get'])
    def users(self, request, pk=None):
        """Get users with this role"""
        role = self.get_object()
        users = role.users.filter(is_active=True)
        serializer = UserListSerializer(users, many=True)
        return Response(serializer.data)


@extend_schema_view(
    list=extend_schema(
        tags=['User Profiles'],
        summary="List user profiles",
        description="List user profiles. Regular users can only see their own profile."
    ),
    create=extend_schema(
        tags=['User Profiles'],
        summary="Create user profile",
        description="Create a new user profile."
    ),
    retrieve=extend_schema(
        tags=['User Profiles'],
        summary="Retrieve user profile",
        description="Retrieve detailed information about a specific user profile."
    ),
    update=extend_schema(
        tags=['User Profiles'],
        summary="Update user profile",
        description="Update a user profile's information."
    ),
    partial_update=extend_schema(
        tags=['User Profiles'],
        summary="Partial update user profile",
        description="Partially update a user profile's information."
    ),
    destroy=extend_schema(
        tags=['User Profiles'],
        summary="Delete user profile",
        description="Delete a user profile."
    )
)
class UserProfileViewSet(viewsets.ModelViewSet):
    """User profile management viewset"""
    queryset = UserProfile.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = APIConstants.PROFILE_SEARCH_FIELDS
    ordering_fields = APIConstants.PROFILE_ORDERING_FIELDS
    ordering = ['-created_at']

    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'list':
            return UserProfileListSerializer
        elif self.action == 'retrieve':
            return UserProfileDetailSerializer
        elif self.action == 'create':
            return UserProfileCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return UserProfileUpdateSerializer
        return UserProfileDetailSerializer

    def get_queryset(self):
        """Filter queryset based on user permissions"""
        queryset = super().get_queryset()
        user = self.request.user

        # Users can only see their own profile unless they have admin permissions
        if not user.is_staff and not user.is_superuser:
            queryset = queryset.filter(user=user)

        return queryset

    def perform_create(self, serializer):
        """Create profile and set current user for audit"""
        profile = serializer.save()
        profile._current_user = self.request.user

    def perform_update(self, serializer):
        """Update profile and set current user for audit"""
        profile = serializer.save()
        profile._current_user = self.request.user


@extend_schema_view(
    list=extend_schema(
        tags=["User Sessions"],
        summary="List user sessions",
        description="List user sessions with filtering.",
        parameters=[
            OpenApiParameter(name="is_active", type=OpenApiTypes.BOOL, description="Filter by active status"),
            OpenApiParameter(name="user", type=OpenApiTypes.INT, description="Filter by user ID"),
            OpenApiParameter(name="ordering", type=OpenApiTypes.STR, description=f"Order by: {', '.join(APIConstants.SESSION_ORDERING_FIELDS)}"),
        ]
    ),
    retrieve=extend_schema(
        tags=["User Sessions"],
        summary="Retrieve user session",
        description="Retrieve detailed information about a specific user session."
    ),
    destroy=extend_schema(
        tags=["User Sessions"],
        summary="Delete user session",
        description="Delete a user session."
    )
)
class UserSessionViewSet(viewsets.ReadOnlyModelViewSet):
    """User session management viewset"""
    queryset = UserSession.objects.all()
    serializer_class = UserSessionSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    ordering_fields = APIConstants.SESSION_ORDERING_FIELDS
    ordering = ['-last_activity']

    def get_queryset(self):
        """Filter queryset based on user permissions"""
        queryset = super().get_queryset()
        user = self.request.user

        # Users can only see their own sessions unless they have admin permissions
        if not user.is_staff and not user.is_superuser:
            queryset = queryset.filter(user=user)

        return queryset

    @extend_schema(
        summary="Expire session",
        description="Mark a session as expired.",
        responses={200: OpenApiTypes.OBJECT}
    )
    @action(detail=True, methods=['post'])
    def expire(self, request, pk=None):
        """Expire a user session"""
        session = self.get_object()
        session.expire()
        return Response({'message': 'Session expired successfully'})

    @extend_schema(
        summary="Bulk expire sessions",
        description="Expire multiple sessions at once. Provide a list of session IDs.",
        request={'application/json': {'properties': {'session_ids': {'type': 'array', 'items': {'type': 'integer'}}}}},
        responses={200: OpenApiTypes.OBJECT}
    )
    @action(detail=False, methods=['post'])
    def bulk_expire(self, request):
        """Expire multiple user sessions"""
        session_ids = request.data.get('session_ids', [])
        if not session_ids:
            return Response({'error': 'session_ids list is required'}, status=status.HTTP_400_BAD_REQUEST)

        queryset = self.get_queryset()
        sessions_to_expire = queryset.filter(id__in=session_ids)

        # Prevent users from expiring their current session
        current_session_key = request.session.session_key
        sessions_to_expire = sessions_to_expire.exclude(session_key=current_session_key)

        expired_count = 0
        for session in sessions_to_expire:
            session.expire()
            expired_count += 1

        return Response({
            'message': f'Successfully expired {expired_count} sessions',
            'expired_sessions': expired_count
        })

    @extend_schema(
        summary="Active sessions count",
        description="Get the count of active sessions for the current user.",
        responses={200: OpenApiTypes.OBJECT}
    )
    @action(detail=False, methods=['get'])
    def active_count(self, request):
        """Get count of active sessions for current user"""
        queryset = self.get_queryset()
        active_count = queryset.filter(is_active=True).count()

        return Response({
            'active_sessions_count': active_count
        })


@extend_schema_view(
    list=extend_schema(
        tags=["Login Attempts"],
        summary="List login attempts",
        description="List login attempts with filtering.",
        parameters=[
            OpenApiParameter(name="success", type=OpenApiTypes.BOOL, description="Filter by success status"),
            OpenApiParameter(name="user", type=OpenApiTypes.INT, description="Filter by user ID"),
            OpenApiParameter(name="ordering", type=OpenApiTypes.STR, description=f"Order by: {', '.join(APIConstants.LOGIN_ATTEMPT_ORDERING_FIELDS)}"),
        ]
    ),
    retrieve=extend_schema(
        tags=["Login Attempts"],
        summary="Retrieve login attempt",
        description="Retrieve detailed information about a specific login attempt."
    )
)
class LoginAttemptViewSet(viewsets.ReadOnlyModelViewSet):
    """Login attempt tracking viewset"""
    queryset = LoginAttempt.objects.all()
    serializer_class = LoginAttemptSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    ordering_fields = APIConstants.LOGIN_ATTEMPT_ORDERING_FIELDS
    ordering = ['-created_at']

    def get_queryset(self):
        """Filter queryset based on user permissions"""
        queryset = super().get_queryset()
        user = self.request.user

        # Users can only see their own login attempts unless they have admin permissions
        if not user.is_staff and not user.is_superuser:
            queryset = queryset.filter(user=user)

        return queryset


@extend_schema_view(
    list=extend_schema(
        tags=["Role History"],
        summary="List role changes",
        description="List user role change history.",
        parameters=[
            OpenApiParameter(name="user", type=OpenApiTypes.INT, description="Filter by user ID"),
            OpenApiParameter(name="changed_by", type=OpenApiTypes.INT, description="Filter by who made the change"),
            OpenApiParameter(name="ordering", type=OpenApiTypes.STR, description=f"Order by: {', '.join(APIConstants.ROLE_ORDERING_FIELDS)}"),
        ]
    ),
    retrieve=extend_schema(
        tags=["Role History"],
        summary="Retrieve role change",
        description="Retrieve detailed information about a specific role change."
    )
)
class UserRoleHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """User role history viewset"""
    queryset = UserRoleHistory.objects.all()
    serializer_class = UserRoleHistorySerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    ordering_fields = APIConstants.ROLE_ORDERING_FIELDS
    ordering = ['-created_at']

    def get_queryset(self):
        """Filter queryset based on user permissions"""
        queryset = super().get_queryset()
        user = self.request.user

        # Users can only see their own role history unless they have admin permissions
        if not user.is_staff and not user.is_superuser:
            queryset = queryset.filter(user=user)

        return queryset


@extend_schema_view(
    list=extend_schema(
        tags=["Permissions"],
        summary="List permissions",
        description="List all permissions with filtering and searching.",
        parameters=[
            OpenApiParameter(name="search", type=OpenApiTypes.STR, description="Search across name and codename"),
            OpenApiParameter(name="app_label", type=OpenApiTypes.STR, description="Filter by app label"),
            OpenApiParameter(name="model", type=OpenApiTypes.STR, description="Filter by model name"),
            OpenApiParameter(name="ordering", type=OpenApiTypes.STR, description="Order by: name, codename, app_label, model"),
        ]
    ),
    create=extend_schema(
        tags=["Permissions"],
        summary="Create permission",
        description="Create a new permission for a specific content type."
    ),
    retrieve=extend_schema(
        tags=["Permissions"],
        summary="Retrieve permission",
        description="Retrieve detailed information about a specific permission."
    ),
    update=extend_schema(
        tags=["Permissions"],
        summary="Update permission",
        description="Update a permission's information. Note: codename and content type cannot be changed."
    ),
    partial_update=extend_schema(
        tags=["Permissions"],
        summary="Partial update permission",
        description="Partially update a permission's information."
    ),
    destroy=extend_schema(
        tags=["Permissions"],
        summary="Delete permission",
        description="Delete a permission. Warning: This may affect user access."
    )
)
class PermissionViewSet(viewsets.ModelViewSet):
    """Permission management viewset"""
    queryset = Permission.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'codename']
    ordering_fields = ['name', 'codename', 'content_type__app_label', 'content_type__model']
    ordering = ['content_type__app_label', 'name']

    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'list':
            return PermissionListSerializer
        elif self.action == 'retrieve':
            return PermissionSerializer
        elif self.action == 'create':
            return PermissionCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return PermissionUpdateSerializer
        return PermissionSerializer

    @extend_schema(
        summary="Get permissions by app",
        description="Get all permissions grouped by app label.",
        responses={200: OpenApiTypes.OBJECT}
    )
    @action(detail=False, methods=['get'])
    def by_app(self, request):
        """Get permissions grouped by app label"""
        permissions = self.get_queryset()
        grouped = {}

        for perm in permissions:
            app_label = perm.content_type.app_label
            if app_label not in grouped:
                grouped[app_label] = []
            grouped[app_label].append(PermissionSerializer(perm).data)

        return Response(grouped)

    @extend_schema(
        summary="Get permissions by model",
        description="Get all permissions for a specific model.",
        parameters=[
            OpenApiParameter(name="app_label", type=OpenApiTypes.STR, required=True, description="App label"),
            OpenApiParameter(name="model", type=OpenApiTypes.STR, required=True, description="Model name"),
        ],
        responses={200: PermissionSerializer(many=True)}
    )
    @action(detail=False, methods=['get'])
    def by_model(self, request):
        """Get permissions for a specific model"""
        app_label = request.query_params.get('app_label')
        model = request.query_params.get('model')

        if not app_label or not model:
            return Response(
                {'error': 'Both app_label and model parameters are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        permissions = self.get_queryset().filter(
            content_type__app_label=app_label,
            content_type__model=model
        )
        serializer = PermissionSerializer(permissions, many=True)
        return Response(serializer.data)


@extend_schema(
    tags=["Statistics"],
    summary="User statistics",
    description="Get basic user statistics.",
    responses={200: OpenApiTypes.OBJECT}
)
class UserStatisticsView(views.APIView):
    """User statistics endpoint"""
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]

    def get(self, request):
        """Get user statistics"""
        total_users = User.objects.count()
        active_users = User.objects.filter(is_active=True).count()
        staff_users = User.objects.filter(is_staff=True).count()

        # Role distribution
        role_distribution = {}
        for role in UserRole.objects.all():
            count = role.users.filter(is_active=True).count()
            if count > 0:
                role_distribution[role.display_name] = count

        stats = {
            "total_users": total_users,
            "active_users": active_users,
            "staff_users": staff_users,
            "role_distribution": role_distribution
        }
        return Response(stats)


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
        status_data = TwoFactorAuthService.get_2fa_status(request.user)
        serializer = TwoFactorStatusSerializer(status_data)
        return Response(serializer.data)