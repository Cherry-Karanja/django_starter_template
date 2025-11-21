"""
Views for the accounts app
"""
from rest_framework import status, generics, permissions, filters, viewsets, views
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
import logging
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiResponse
from drf_spectacular.types import OpenApiTypes
from .models import User, UserSession, LoginAttempt, UserRole, UserProfile, UserRoleHistory
from .serializers import (
    UserListSerializer, UserDetailSerializer, UserCreateSerializer, UserUpdateSerializer,
    UserRoleListSerializer, UserRoleDetailSerializer, UserRoleCreateSerializer, UserRoleUpdateSerializer,
    UserProfileListSerializer, UserProfileDetailSerializer, UserProfileCreateSerializer, UserProfileUpdateSerializer,
    UserRoleHistorySerializer, UserSessionSerializer, LoginAttemptSerializer,
    UserPermissionsSerializer, UserRoleChangeRequestSerializer, UserRoleChangeResponseSerializer,
    UserApprovalSerializer, PermissionSerializer, PermissionCreateSerializer, PermissionUpdateSerializer, PermissionListSerializer,
    UserPermissionUpdateSerializer, UserPermissionResponseSerializer, PermissionUpdateRequestSerializer,
    UserApprovalRequestSerializer, RoleChangeRequestSerializer,
)
from apps.core.permissions import IsAdminOrReadOnly
from .constants import APIConstants
from .services import UserService
from .schema import (
    common_responses,
    user_parameters,
    role_parameters,
    permission_parameters,
    session_parameters,
    login_attempt_parameters,
    user_stats_response,
    session_stats_response
)

User = get_user_model()
logger = logging.getLogger(__name__)

@extend_schema_view(
    list=extend_schema(
        tags=["Users"],
        summary="List users",
        description="Retrieve a list of users with optional filtering by role, status, and search capabilities.",
        parameters=user_parameters,
        responses={
            200: UserListSerializer(many=True),
            **common_responses
        }
    ),
    create=extend_schema(
        tags=["Users"],
        summary="Create user",
        description="Create a new user account with role assignment and profile information.",
        request=UserCreateSerializer,
        responses={
            201: UserDetailSerializer,
            **common_responses
        }
    ),
    retrieve=extend_schema(
        tags=["Users"],
        summary="Retrieve user",
        description="Retrieve detailed information about a specific user including profile and permissions.",
        responses={
            200: UserDetailSerializer,
            **common_responses
        }
    ),
    update=extend_schema(
        tags=["Users"],
        summary="Update user",
        description="Update a user's information including role changes and profile updates.",
        request=UserUpdateSerializer,
        responses={
            200: UserDetailSerializer,
            **common_responses
        }
    ),
    partial_update=extend_schema(
        tags=["Users"],
        summary="Partial update user",
        description="Partially update a user's information without requiring all fields.",
        request=UserUpdateSerializer,
        responses={
            200: UserDetailSerializer,
            **common_responses
        }
    ),
    destroy=extend_schema(
        tags=["Users"],
        summary="Delete user",
        description="Delete a user account and all associated data.",
        responses={
            204: None,
            **common_responses
        }
    ),
    approve=extend_schema(
        tags=["Users"],
        summary="Approve user",
        description="Approve a user account for access after registration or role change.",
        request=UserApprovalRequestSerializer,
        responses={
            200: UserApprovalSerializer,
            **common_responses
        }
    ),
    change_role=extend_schema(
        tags=["Users"],
        summary="Change user role",
        description="Change the role assignment for a specific user.",
        request=RoleChangeRequestSerializer,
        responses={
            200: UserRoleChangeResponseSerializer,
            **common_responses
        }
    ),
    my_permissions=extend_schema(
        tags=["Users"],
        summary="Get current user permissions",
        description="Retrieve all permissions assigned to the currently authenticated user.",
        responses={
            200: UserPermissionsSerializer,
            **common_responses
        }
    ),
    update_permissions=extend_schema(
        tags=["Users"],
        summary="Update user permissions",
        description="Grant or revoke specific permissions for a user.",
        request=PermissionUpdateRequestSerializer,
        responses={
            200: UserPermissionResponseSerializer,
            **common_responses
        }
    )
)
@extend_schema(tags=["Users"])
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
        tags=["Users"],
        summary="Approve user",
        description="Approve a user account for access after registration or role change.",
        request=UserApprovalRequestSerializer,
        responses={
            200: UserApprovalSerializer,
            **common_responses
        }
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
        tags=["Users"],
        summary="Change user role",
        description="Change the role assignment for a specific user.",
        request=RoleChangeRequestSerializer,
        responses={
            200: UserRoleChangeResponseSerializer,
            **common_responses
        }
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
        tags=["Users"],
        summary="Get current user permissions",
        description="Retrieve all permissions assigned to the currently authenticated user.",
        responses={
            200: UserPermissionsSerializer,
            **common_responses
        }
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
    @extend_schema(
        tags=["Users"],
        summary="Update user permissions",
        description="Grant or revoke specific permissions for a user.",
        request=PermissionUpdateRequestSerializer,
        responses={
            200: UserPermissionResponseSerializer,
            **common_responses
        }
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
        description="Retrieve a list of user roles with optional filtering by status and search capabilities.",
        parameters=role_parameters,
        responses={
            200: UserRoleListSerializer(many=True),
            **common_responses
        }
    ),
    create=extend_schema(
        tags=["Roles"],
        summary="Create role",
        description="Create a new user role with associated permissions.",
        request=UserRoleCreateSerializer,
        responses={
            201: UserRoleDetailSerializer,
            **common_responses
        }
    ),
    retrieve=extend_schema(
        tags=["Roles"],
        summary="Retrieve role",
        description="Retrieve detailed information about a specific user role including permissions.",
        responses={
            200: UserRoleDetailSerializer,
            **common_responses
        }
    ),
    update=extend_schema(
        tags=["Roles"],
        summary="Update role",
        description="Update a user role's information and associated permissions.",
        request=UserRoleUpdateSerializer,
        responses={
            200: UserRoleDetailSerializer,
            **common_responses
        }
    ),
    partial_update=extend_schema(
        tags=["Roles"],
        summary="Partial update role",
        description="Partially update a user role's information without requiring all fields.",
        request=UserRoleUpdateSerializer,
        responses={
            200: UserRoleDetailSerializer,
            **common_responses
        }
    ),
    destroy=extend_schema(
        tags=["Roles"],
        summary="Delete role",
        description="Delete a user role. This will fail if users are still assigned to this role.",
        responses={
            204: None,
            **common_responses
        }
    ),
    users=extend_schema(
        tags=["Roles"],
        summary="Get role users",
        description="Retrieve all active users assigned to a specific role.",
        responses={
            200: UserListSerializer(many=True),
            **common_responses
        }
    )
)
@extend_schema(tags=["Roles"])
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
        tags=["Roles"],
        summary="Get role users",
        description="Retrieve all active users assigned to a specific role.",
        responses={
            200: UserListSerializer(many=True),
            **common_responses
        }
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
        tags=["User Profiles"],
        summary="List user profiles",
        description="Retrieve a list of user profiles. Regular users can only see their own profile.",
        parameters=[
            OpenApiParameter(
                name="search",
                type=OpenApiTypes.STR,
                description="Search across user information and profile data",
                required=False
            ),
            OpenApiParameter(
                name="ordering",
                type=OpenApiTypes.STR,
                description="Order by field (prefix with - for descending)",
                required=False
            ),
        ],
        responses={
            200: UserProfileListSerializer(many=True),
            **common_responses
        }
    ),
    create=extend_schema(
        tags=["User Profiles"],
        summary="Create user profile",
        description="Create a new user profile with extended information.",
        request=UserProfileCreateSerializer,
        responses={
            201: UserProfileDetailSerializer,
            **common_responses
        }
    ),
    retrieve=extend_schema(
        tags=["User Profiles"],
        summary="Retrieve user profile",
        description="Retrieve detailed information about a specific user profile.",
        responses={
            200: UserProfileDetailSerializer,
            **common_responses
        }
    ),
    update=extend_schema(
        tags=["User Profiles"],
        summary="Update user profile",
        description="Update a user profile's information and preferences.",
        request=UserProfileUpdateSerializer,
        responses={
            200: UserProfileDetailSerializer,
            **common_responses
        }
    ),
    partial_update=extend_schema(
        tags=["User Profiles"],
        summary="Partial update user profile",
        description="Partially update a user profile's information without requiring all fields.",
        request=UserProfileUpdateSerializer,
        responses={
            200: UserProfileDetailSerializer,
            **common_responses
        }
    ),
    destroy=extend_schema(
        tags=["User Profiles"],
        summary="Delete user profile",
        description="Delete a user profile and associated data.",
        responses={
            204: None,
            **common_responses
        }
    )
)
@extend_schema(tags=["User Profiles"])
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
        description="Retrieve a list of user sessions with optional filtering by status, user, and risk score.",
        parameters=session_parameters,
        responses={
            200: UserSessionSerializer(many=True),
            **common_responses
        }
    ),
    retrieve=extend_schema(
        tags=["User Sessions"],
        summary="Retrieve user session",
        description="Retrieve detailed information about a specific user session including device and location data.",
        responses={
            200: UserSessionSerializer,
            **common_responses
        }
    )
)
@extend_schema(tags=["User Sessions"])
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
        description="Retrieve a list of login attempts with optional filtering by success status, user, and failure reasons.",
        parameters=login_attempt_parameters,
        responses={
            200: LoginAttemptSerializer(many=True),
            **common_responses
        }
    ),
    retrieve=extend_schema(
        tags=["Login Attempts"],
        summary="Retrieve login attempt",
        description="Retrieve detailed information about a specific login attempt including IP address and failure details.",
        responses={
            200: LoginAttemptSerializer,
            **common_responses
        }
    )
)
@extend_schema(tags=["Login Attempts"])
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
        tags=["User Role History"],
        summary="List role changes",
        description="Retrieve a list of user role change history with optional filtering by user and change author.",
        parameters=[
            OpenApiParameter(
                name="user",
                type=OpenApiTypes.INT,
                description="Filter by user ID",
                required=False
            ),
            OpenApiParameter(
                name="changed_by",
                type=OpenApiTypes.INT,
                description="Filter by who made the change",
                required=False
            ),
            OpenApiParameter(
                name="ordering",
                type=OpenApiTypes.STR,
                description="Order by field (prefix with - for descending)",
                required=False
            ),
        ],
        responses={
            200: UserRoleHistorySerializer(many=True),
            **common_responses
        }
    ),
    retrieve=extend_schema(
        tags=["User Role History"],
        summary="Retrieve role change",
        description="Retrieve detailed information about a specific role change including old and new roles.",
        responses={
            200: UserRoleHistorySerializer,
            **common_responses
        }
    )
)
@extend_schema(tags=["User Role History"])
class UserRoleHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """User role history viewset"""
    queryset = UserRoleHistory.objects.all()
    serializer_class = UserRoleHistorySerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    ordering_fields = APIConstants.ROLE_ORDERING_FIELDS
    ordering = ['-created_at']
    http_method_names = ['get', 'head', 'options']

    def get_queryset(self):
        """Filter queryset based on user permissions"""
        queryset = super().get_queryset()
        user = self.request.user

        # Users can only see their own role history unless they have admin permissions
        if not user.is_staff and not user.is_superuser:
            queryset = queryset.filter(user=user)

        return queryset



@extend_schema(tags=["Permissions"])
@extend_schema_view(
    list=extend_schema(
        summary="List permissions",
        description="Retrieve a paginated list of all permissions in the system.",
        parameters=permission_parameters,
        responses={
            200: PermissionSerializer(many=True),
            **common_responses
        }
    ),
    retrieve=extend_schema(
        summary="Get permission details",
        description="Retrieve detailed information about a specific permission.",
        parameters=permission_parameters,
        responses={
            200: PermissionSerializer,
            **common_responses
        }
    ),
    create=extend_schema(
        summary="Create permission",
        description="Create a new permission in the system.",
        parameters=permission_parameters,
        responses={
            201: PermissionSerializer,
            **common_responses
        }
    ),
    update=extend_schema(
        summary="Update permission",
        description="Update an existing permission's information.",
        parameters=permission_parameters,
        responses={
            200: PermissionSerializer,
            **common_responses
        }
    ),
    partial_update=extend_schema(
        summary="Partial update permission",
        description="Partially update an existing permission's information.",
        parameters=permission_parameters,
        responses={
            200: PermissionSerializer,
            **common_responses
        }
    ),
    destroy=extend_schema(
        summary="Delete permission",
        description="Delete a permission from the system.",
        parameters=permission_parameters,
        responses={
            204: {"description": "Permission deleted successfully"},
            **common_responses
        }
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

