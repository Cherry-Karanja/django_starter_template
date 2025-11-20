"""
Constants for the accounts app
"""
from django.utils.translation import gettext_lazy as _


# User Role Constants
class UserRoleConstants:
    """Constants for user roles"""

    # Basic roles - can be customized per project
    STAFF = 'staff'
    MANAGER = 'manager'
    ADMIN = 'admin'
    SUPER_ADMIN = 'super_admin'

    # Role choices for forms and validation
    ROLE_CHOICES = [
        (STAFF, _('Staff')),
        (MANAGER, _('Manager')),
        (ADMIN, _('Administrator')),
        (SUPER_ADMIN, _('Super Administrator')),
    ]

    # Default role for new users
    DEFAULT_ROLE = STAFF


# Role Definitions for Management Commands
ROLE_DEFINITIONS = {
    UserRoleConstants.STAFF: {
        'description': _('Basic staff member with limited access'),
        'display_name': _('Staff'),
        'permissions': [
            'view_user',
            'view_userprofile',
        ]
    },
    UserRoleConstants.MANAGER: {
        'description': _('Manager with additional permissions to manage team members'),
        'display_name': _('Manager'),
        'permissions': [
            'view_user',
            'change_user',
            'view_userprofile',
            'change_userprofile',
            'view_userrole',
        ]
    },
    UserRoleConstants.ADMIN: {
        'description': _('Administrator with full access to user management'),
        'display_name': _('Admin'),
        'permissions': [
            'view_user',
            'add_user',
            'change_user',
            'delete_user',
            'view_userprofile',
            'add_userprofile',
            'change_userprofile',
            'delete_userprofile',
            'view_userrole',
            'add_userrole',
            'change_userrole',
            'delete_userrole',
        ]
    },
    UserRoleConstants.SUPER_ADMIN: {
        'description': _('Super administrator with all permissions'),
        'display_name': _('Super Admin'),
        'permissions': []  # Super admin gets all permissions automatically
    }
}


# Permission Constants
class PermissionConstants:
    """Constants for permission codenames"""

    # User permissions
    VIEW_USER = 'view_user'
    ADD_USER = 'add_user'
    CHANGE_USER = 'change_user'
    DELETE_USER = 'delete_user'

    # User role permissions
    VIEW_USERROLE = 'view_userrole'
    ADD_USERROLE = 'add_userrole'
    CHANGE_USERROLE = 'change_userrole'
    DELETE_USERROLE = 'delete_userrole'

    # User profile permissions
    VIEW_USERPROFILE = 'view_userprofile'
    ADD_USERPROFILE = 'add_userprofile'
    CHANGE_USERPROFILE = 'change_userprofile'
    DELETE_USERPROFILE = 'delete_userprofile'

    # User session permissions
    VIEW_USERSESSION = 'view_usersession'
    ADD_USERSESSION = 'add_usersession'
    CHANGE_USERSESSION = 'change_usersession'
    DELETE_USERSESSION = 'delete_usersession'

    # Login attempt permissions
    VIEW_LOGINATTEMPT = 'accounts.view_loginattempt'
    ADD_LOGINATTEMPT = 'accounts.add_loginattempt'
    CHANGE_LOGINATTEMPT = 'accounts.change_loginattempt'
    DELETE_LOGINATTEMPT = 'accounts.delete_loginattempt'

    # Special permissions
    CAN_MANAGE_USERS = 'accounts.can_manage_users'
    CAN_VIEW_DASHBOARD = 'accounts.can_view_dashboard'
    CAN_APPROVE_USERS = 'accounts.can_approve_users'
    CAN_CHANGE_USER_ROLES = 'accounts.can_change_user_roles'


# Default role permissions mapping
DEFAULT_ROLE_PERMISSIONS = {
    UserRoleConstants.STAFF: [
        PermissionConstants.VIEW_USER,
        PermissionConstants.CAN_VIEW_DASHBOARD,
    ],
    UserRoleConstants.MANAGER: [
        PermissionConstants.VIEW_USER,
        PermissionConstants.ADD_USER,
        PermissionConstants.CHANGE_USER,
        PermissionConstants.VIEW_USERPROFILE,
        PermissionConstants.ADD_USERPROFILE,
        PermissionConstants.CHANGE_USERPROFILE,
        PermissionConstants.CAN_MANAGE_USERS,
        PermissionConstants.CAN_VIEW_DASHBOARD,
        PermissionConstants.CAN_APPROVE_USERS,
    ],
    UserRoleConstants.ADMIN: [
        # Full access to accounts app
        PermissionConstants.VIEW_USER,
        PermissionConstants.ADD_USER,
        PermissionConstants.CHANGE_USER,
        PermissionConstants.DELETE_USER,
        PermissionConstants.VIEW_USERROLE,
        PermissionConstants.ADD_USERROLE,
        PermissionConstants.CHANGE_USERROLE,
        PermissionConstants.DELETE_USERROLE,
        PermissionConstants.VIEW_USERPROFILE,
        PermissionConstants.ADD_USERPROFILE,
        PermissionConstants.CHANGE_USERPROFILE,
        PermissionConstants.DELETE_USERPROFILE,
        PermissionConstants.VIEW_USERSESSION,
        PermissionConstants.ADD_USERSESSION,
        PermissionConstants.CHANGE_USERSESSION,
        PermissionConstants.DELETE_USERSESSION,
        PermissionConstants.VIEW_LOGINATTEMPT,
        PermissionConstants.ADD_LOGINATTEMPT,
        PermissionConstants.CHANGE_LOGINATTEMPT,
        PermissionConstants.DELETE_LOGINATTEMPT,
        PermissionConstants.CAN_MANAGE_USERS,
        PermissionConstants.CAN_VIEW_DASHBOARD,
        PermissionConstants.CAN_APPROVE_USERS,
        PermissionConstants.CAN_CHANGE_USER_ROLES,
    ],
    UserRoleConstants.SUPER_ADMIN: [
        # All permissions across the system
        '*',
    ],
}


# User Status Constants
class UserStatusConstants:
    """Constants for user status and approval states"""

    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'
    SUSPENDED = 'suspended'

    STATUS_CHOICES = [
        (PENDING, _('Pending Approval')),
        (APPROVED, _('Approved')),
        (REJECTED, _('Rejected')),
        (SUSPENDED, _('Suspended')),
    ]


# Session Constants
class SessionConstants:
    """Constants for user sessions"""

    MAX_CONCURRENT_SESSIONS = 5
    SESSION_TIMEOUT_HOURS = 24
    INACTIVE_TIMEOUT_MINUTES = 30


# Login Attempt Constants
class LoginAttemptConstants:
    """Constants for login attempt tracking"""

    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    RESET_FAILED_ATTEMPTS_AFTER_MINUTES = 30


# API Constants
class APIConstants:
    """Constants for API configuration"""

    DEFAULT_PAGE_SIZE = 20
    MAX_PAGE_SIZE = 100

    # Ordering options
    USER_ORDERING_FIELDS = ['created_at', 'last_login', 'email', 'first_name', 'last_name', 'employee_id']
    ROLE_ORDERING_FIELDS = ['name', 'created_at', 'is_active']
    PROFILE_ORDERING_FIELDS = ['created_at', 'updated_at', 'user__email']
    SESSION_ORDERING_FIELDS = ['created_at', 'last_activity', 'user__email']
    LOGIN_ATTEMPT_ORDERING_FIELDS = ['created_at', 'user__email', 'success']

    # Search fields
    USER_SEARCH_FIELDS = ['email', 'first_name', 'last_name', 'employee_id']
    ROLE_SEARCH_FIELDS = ['name', 'display_name', 'description']
    PROFILE_SEARCH_FIELDS = ['user__email', 'user__first_name', 'user__last_name', 'bio']
    SESSION_SEARCH_FIELDS = ['user__email', 'user__first_name', 'user__last_name', 'ip_address']
    LOGIN_ATTEMPT_SEARCH_FIELDS = ['user__email', 'user__first_name', 'user__last_name', 'ip_address']