"""
Services for user management and authentication
"""
from django.contrib.auth import get_user_model
from .models import UserRole, UserProfile, UserRoleHistory
from .constants import UserRoleConstants
import logging

logger = logging.getLogger('accounts.services')
User = get_user_model()


class UserService:
    """Service class for user-related operations"""

    @staticmethod
    def create_user_with_role(email, password, first_name, last_name, role_name=None, **extra_fields):
        """Create a new user with specified role"""
        try:
            # Use default role if none specified
            if not role_name:
                role_name = UserRoleConstants.DEFAULT_ROLE

            # Get or create role
            role, created = UserRole.objects.get_or_create(
                name=role_name,
                defaults={
                    'display_name': role_name.replace('_', ' ').title(),
                    'description': f'Default {role_name} role'
                }
            )

            # Create user
            user = User.objects.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role=role,
                **extra_fields
            )

            # Create user profile
            UserProfile.objects.create(user=user)

            logger.info(f"User created: {email} with role {role_name}")
            return user

        except Exception as e:
            logger.error(f"Error creating user {email}: {str(e)}")
            raise

    @staticmethod
    def change_user_role(user, new_role_name, changed_by=None, reason=""):
        """Change user role with audit trail"""
        try:
            old_role = user.role
            new_role = UserRole.objects.get(name=new_role_name)

            # Update user role
            user.role = new_role
            user.save(update_fields=['role'])

            # Create audit record
            UserRoleHistory.objects.create(
                user=user,
                old_role=old_role,
                new_role=new_role,
                changed_by=changed_by,
                reason=reason
            )

            logger.info(f"User role changed: {user.email} from {old_role} to {new_role}")
            return True

        except UserRole.DoesNotExist:
            logger.error(f"Role {new_role_name} does not exist")
            return False
        except Exception as e:
            logger.error(f"Error changing role for {user.email}: {str(e)}")
            return False

    @staticmethod
    def get_user_permissions(user):
        """Get all permissions for a user"""
        if not user.role:
            return []

        if user.role.name == UserRoleConstants.SUPER_ADMIN:
            # Super admin has all permissions
            from django.contrib.auth.models import Permission
            return list(Permission.objects.values_list('codename', flat=True))

        return list(user.role.permissions.values_list('codename', flat=True))

    @staticmethod
    def check_user_permission(user, permission_codename):
        """Check if user has specific permission"""
        if not user.role:
            return False

        if user.role.name == UserRoleConstants.SUPER_ADMIN:
            return True

        return user.role.permissions.filter(codename=permission_codename).exists()

    @staticmethod
    def approve_user(user, approved_by):
        """Approve a user account"""
        try:
            user.profile.approve(approved_by)
            logger.info(f"User {user.email} approved by {approved_by.email}")
            return True
        except Exception as e:
            logger.error(f"Error approving user {user.email}: {str(e)}")
            return False

    @staticmethod
    def deactivate_user(user, deactivated_by=None, reason=""):
        """Deactivate a user account"""
        try:
            user.is_active = False
            user.save(update_fields=['is_active'])

            # Log deactivation
            logger.info(f"User {user.email} deactivated by {deactivated_by.email if deactivated_by else 'system'}: {reason}")
            return True
        except Exception as e:
            logger.error(f"Error deactivating user {user.email}: {str(e)}")
            return False

class RoleService:
    """Service class for role management"""

    @staticmethod
    def create_default_roles():
        """Create default roles with permissions for the new project"""
        from django.contrib.auth.models import Permission
        from .constants import DEFAULT_ROLE_PERMISSIONS

        roles_created = 0
        for role_name, permission_codenames in DEFAULT_ROLE_PERMISSIONS.items():
            role, created = UserRole.objects.get_or_create(
                name=role_name,
                defaults={
                    'display_name': role_name.replace('_', ' ').title(),
                    'description': f'Default {role_name} role'
                }
            )

            if created or not role.permissions.exists():
                if role_name != UserRoleConstants.SUPER_ADMIN:
                    permissions = Permission.objects.filter(codename__in=permission_codenames)
                    role.permissions.set(permissions)
                    logger.info(f"Created role {role_name} with {permissions.count()} permissions")
                roles_created += 1

        return roles_created

    @staticmethod
    def assign_permissions_to_role(role_name, permission_codenames):
        """Assign permissions to a role"""
        try:
            from django.contrib.auth.models import Permission

            role = UserRole.objects.get(name=role_name)
            permissions = Permission.objects.filter(codename__in=permission_codenames)
            role.permissions.set(permissions)

            logger.info(f"Assigned {permissions.count()} permissions to role {role_name}")
            return True

        except UserRole.DoesNotExist:
            logger.error(f"Role {role_name} does not exist")
            return False
        except Exception as e:
            logger.error(f"Error assigning permissions to role {role_name}: {str(e)}")
            return False

    @staticmethod
    def update_role_permissions(role, permission_codenames):
        """Update permissions for a role"""
        try:
            from django.contrib.auth.models import Permission

            permissions = Permission.objects.filter(codename__in=permission_codenames)
            role.permissions.set(permissions)

            logger.info(f"Updated permissions for role {role.name}: {permissions.count()} permissions")
            return True

        except Exception as e:
            logger.error(f"Error updating permissions for role {role.name}: {str(e)}")
            return False

    @staticmethod
    def get_role_users(role_name):
        """Get all users with a specific role"""
        try:
            role = UserRole.objects.get(name=role_name)
            return User.objects.filter(role=role, is_active=True)
        except UserRole.DoesNotExist:
            return User.objects.none()

    @staticmethod
    def get_users_by_role():
        """Get users grouped by role"""
        roles = UserRole.objects.prefetch_related('users').all()
        result = {}

        for role in roles:
            result[role.name] = {
                'role': role,
                'users': list(role.users.filter(is_active=True))
            }

        return result

