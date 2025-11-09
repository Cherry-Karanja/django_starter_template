"""
Accounts app models for user management and authentication
"""
from datetime import timedelta
from django.db import models
from django.contrib.auth.models import AbstractUser, Permission
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.conf import settings
from apps.core.models import TimestampedModel, AuditMixin, SoftDeleteMixin, BaseModel
import uuid


class UserRole(TimestampedModel, AuditMixin, SoftDeleteMixin):
    """
    User roles for role-based access control
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    name = models.CharField(
        max_length=100,
        unique=True,
        help_text=_("Unique role identifier")
    )
    display_name = models.CharField(
        max_length=100,
        help_text=_("Human-readable role name")
    )
    description = models.TextField(
        blank=True,
        help_text=_("Role description")
    )
    is_active = models.BooleanField(
        default=True,
        help_text=_("Whether this role is active")
    )
    permissions = models.ManyToManyField(
        Permission,
        blank=True,
        related_name='user_roles',
        help_text=_("Permissions assigned to this role")
    )

    class Meta:
        app_label = 'accounts'
        ordering = ['display_name']
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['is_active']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return self.display_name

    def clean(self):
        """Validate role data"""
        if not self.name:
            raise ValidationError(_("Role name is required"))
        if not self.display_name:
            raise ValidationError(_("Display name is required"))


class User(AbstractUser, BaseModel):
    """
    Custom user model with email authentication and role-based access
    """
    # Override username field - not used for authentication
    username = models.CharField(
        max_length=150,
        blank=True,
        null=True,
        help_text=_("Not used for authentication - kept for compatibility")
    )

    # Email as primary identifier
    email = models.EmailField(
        unique=True,
        help_text=_("Primary email address for authentication")
    )

    # Role-based access control
    role = models.ForeignKey(
        UserRole,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='users',
        help_text=_("User's role for permissions")
    )

    # Additional fields
    employee_id = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        unique=True,
        help_text=_("Employee ID for organizational tracking")
    )

    # Security fields
    failed_login_attempts = models.PositiveIntegerField(
        default=0,
        help_text=_("Number of consecutive failed login attempts")
    )
    account_locked_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When the account lock expires")
    )
    last_login_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text=_("IP address of last successful login")
    )

    # Approval and verification fields
    is_approved = models.BooleanField(
        default=False,
        help_text=_("Whether the user account has been approved by an administrator")
    )
    is_verified = models.BooleanField(
        default=False,
        help_text=_("Whether the user has verified their email or identity")
    )
    must_change_password = models.BooleanField(
        default=False,
        help_text=_("Whether the user must change their password on next login")
    )
    password_changed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When the password was last changed")
    )

    """ timestamp fields"""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Override required fields
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        app_label = 'accounts'
        ordering = ['-date_joined']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['employee_id']),
            models.Index(fields=['is_active']),
            models.Index(fields=['date_joined']),
            models.Index(fields=['role']),
        ]

    def __str__(self):
        return f"{self.get_full_name()} ({self.email})"

    def clean(self):
        """Validate user data"""
        if not self.email:
            raise ValidationError(_("Email is required"))
        if self.employee_id and User.objects.filter(
            employee_id=self.employee_id
        ).exclude(pk=self.pk).exists():
            raise ValidationError(_("Employee ID must be unique"))

    def get_full_name(self):
        """Return the first_name plus the last_name, with a space in between."""
        full_name = f"{self.first_name} {self.last_name}".strip()
        return full_name or self.email

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name or self.email

    def has_role_permission(self, permission_codename):
        """Check if user has permission through their role"""
        if not self.role or not self.role.is_active:
            return False

        # Super admin has all permissions
        if hasattr(self.role, 'name') and self.role.name == 'super_admin':
            return True

        return self.role.permissions.filter(codename=permission_codename).exists()

    def get_all_permissions(self):
        """Get all permissions for this user"""
        if not self.role or not self.role.is_active:
            return set()

        if hasattr(self.role, 'name') and self.role.name == 'super_admin':
            # Super admin has all permissions
            from django.contrib.auth.models import Permission
            return set(Permission.objects.values_list('codename', flat=True))

        return set(self.role.permissions.values_list('codename', flat=True))

    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until and self.account_locked_until > timezone.now():
            return True
        elif self.account_locked_until:
            # Lock period expired, reset counters
            self.account_locked_until = None
            self.failed_login_attempts = 0
            self.save(update_fields=['account_locked_until', 'failed_login_attempts'])
        return False

    def reset_failed_login_attempts(self):
        """Reset failed login attempt counter"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save(update_fields=['failed_login_attempts', 'account_locked_until'])

    def increment_failed_login_attempts(self):
        """Increment failed login attempts and lock if necessary"""
        self.failed_login_attempts += 1

        # Lock account after 5 failed attempts for 15 minutes
        if self.failed_login_attempts >= 5:
            self.account_locked_until = timezone.now() + timezone.timedelta(minutes=15)

        self.save(update_fields=['failed_login_attempts', 'account_locked_until'])


class UserProfile(TimestampedModel, AuditMixin, SoftDeleteMixin):
    """
    Extended user profile information
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile',
        help_text=_("User this profile belongs to")
    )

    # Profile information
    bio = models.TextField(
        blank=True,
        help_text=_("User biography")
    )
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        help_text=_("Phone number")
    )
    department = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Department or division")
    )
    job_title = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Job title or position")
    )

    # Status and approval
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', _('Pending Approval')),
            ('approved', _('Approved')),
            ('rejected', _('Rejected')),
            ('suspended', _('Suspended')),
        ],
        default='pending',
        help_text=_("User approval status")
    )

    # Additional metadata
    approved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approved_users',
        help_text=_("User who approved this profile")
    )
    approved_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When this profile was approved")
    )

    # User preferences
    preferred_language = models.CharField(
        max_length=10,
        default='en',
        help_text=_("User's preferred language code")
    )
    interface_theme = models.CharField(
        max_length=20,
        choices=[
            ('light', _('Light Theme')),
            ('dark', _('Dark Theme')),
            ('auto', _('Auto Theme')),
        ],
        default='light',
        help_text=_("User interface theme preference")
    )
    allow_notifications = models.BooleanField(
        default=True,
        help_text=_("Whether to allow email notifications")
    )

    # Privacy settings
    show_email = models.BooleanField(
        default=False,
        help_text=_("Whether to show email address publicly")
    )
    show_phone = models.BooleanField(
        default=False,
        help_text=_("Whether to show phone number publicly")
    )

    class Meta:
        app_label = 'accounts'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"Profile for {self.user.email}"

    def approve(self, approved_by):
        """Approve the user profile"""
        self.status = 'approved'
        self.approved_by = approved_by
        self.approved_at = timezone.now()
        self.save()

    def reject(self):
        """Reject the user profile"""
        self.status = 'rejected'
        self.save()

    def suspend(self):
        """Suspend the user profile"""
        self.status = 'suspended'
        self.save()


class UserSession(TimestampedModel, AuditMixin):
    """
    Track user sessions for security monitoring
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sessions',
        help_text=_("User this session belongs to")
    )

    session_key = models.CharField(
        max_length=40,
        unique=True,
        help_text=_("Django session key")
    )

    ip_address = models.GenericIPAddressField(
        help_text=_("IP address of the session")
    )

    user_agent = models.TextField(
        blank=True,
        help_text=_("User agent string")
    )

    # Additional tracking fields
    device_type = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Type of device used")
    )
    device_os = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Operating system of device")
    )
    browser = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Browser used for session")
    )
    location_info = models.JSONField(
        null=True,
        blank=True,
        help_text=_("Geographic location information")
    )

    is_active = models.BooleanField(
        default=True,
        help_text=_("Whether this session is currently active")
    )

    expires_at = models.DateTimeField(
        help_text=_("When this session expires")
    )

    last_activity = models.DateTimeField(
        default=timezone.now,
        help_text=_("Last activity timestamp")
    )

    class Meta:
        app_label = 'accounts'
        ordering = ['-last_activity']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['session_key']),
            models.Index(fields=['is_active']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['last_activity']),
        ]

    def __str__(self):
        return f"Session for {self.user.email} from {self.ip_address}"

    def is_expired(self):
        """Check if session has expired"""
        return timezone.now() > self.expires_at

    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])

    def expire(self):
        """Mark session as expired"""
        self.is_active = False
        self.save(update_fields=['is_active'])

    def revoke(self, reason=None):
        """Revoke session with optional reason"""
        self.is_active = False
        # Could add reason to a field if needed in the future
        self.save(update_fields=['is_active'])

    @classmethod
    def create_session(cls, user, request, created_via='login'):
        """
        Create a new session record for tracking
        
        Args:
            user: The user this session belongs to
            request: The HTTP request object
            created_via: How this session was created (login, middleware_recovery, etc.)
        """
        from apps.core.utils import get_client_ip
        
        session_key = request.session.session_key
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        return cls.objects.create(
            user=user,
            session_key=session_key,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=timezone.now() + timedelta(days=7)  # 7 days
        )

    @classmethod
    def detect_suspicious_sessions(cls, user, request):
        """
        Detect potentially suspicious sessions for a user
        
        Returns a list of suspicious sessions based on:
        - Multiple active sessions from different IP addresses
        - Sessions from unusual locations (basic check)
        """
        if not user or not user.is_authenticated:
            return []
            
        # Get current IP address
        from apps.core.utils import get_client_ip
        current_ip = get_client_ip(request)
        
        # Get all active sessions for this user
        active_sessions = cls.objects.filter(
            user=user,
            is_active=True,
            expires_at__gt=timezone.now()
        ).exclude(ip_address=current_ip)
        
        suspicious_sessions = []
        
        # Check for multiple sessions from different IPs
        if active_sessions.count() > 2:  # More than 2 sessions from different IPs
            suspicious_sessions.extend(active_sessions)
        
        # Check for sessions from very different locations (basic check)
        # This is a simplified version - in production you'd use geo-IP databases
        current_ip_parts = current_ip.split('.') if current_ip else []
        for session in active_sessions:
            if session.ip_address:
                session_ip_parts = session.ip_address.split('.')
                # Simple check: if first two octets differ significantly
                if (len(current_ip_parts) >= 2 and len(session_ip_parts) >= 2 and
                    current_ip_parts[0] != session_ip_parts[0]):
                    suspicious_sessions.append(session)
        
        # Remove duplicates
        return list(set(suspicious_sessions))


class LoginAttempt(TimestampedModel):
    """
    Track login attempts for security monitoring
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    email = models.EmailField(
        help_text=_("Email address used for login attempt")
    )

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='login_attempts',
        help_text=_("User associated with this attempt (if successful)")
    )

    ip_address = models.GenericIPAddressField(
        help_text=_("IP address of the login attempt")
    )

    user_agent = models.TextField(
        blank=True,
        help_text=_("User agent string")
    )

    # Additional tracking fields
    session_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Session ID for tracking")
    )
    failure_reason = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Reason for login failure")
    )
    location_info = models.JSONField(
        null=True,
        blank=True,
        help_text=_("Geographic location information")
    )
    device_type = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Type of device used")
    )
    device_os = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Operating system of device")
    )
    browser = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Browser used for login")
    )

    success = models.BooleanField(
        default=False,
        help_text=_("Whether the login attempt was successful")
    )

    class Meta:
        app_label = 'accounts'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['user']),
            models.Index(fields=['success']),
            models.Index(fields=['created_at']),
            models.Index(fields=['ip_address']),
        ]

    def __str__(self):
        status = "successful" if self.success else "failed"
        return f"{status.capitalize()} login attempt for {self.email} from {self.ip_address}"


class UserRoleHistory(TimestampedModel, AuditMixin):
    """
    Audit trail for user role changes
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='role_history',
        help_text=_("User whose role was changed")
    )

    old_role = models.ForeignKey(
        UserRole,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='role_changes_from',
        help_text=_("Previous role")
    )

    new_role = models.ForeignKey(
        UserRole,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='role_changes_to',
        help_text=_("New role")
    )

    changed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='role_changes_made',
        help_text=_("User who made the role change")
    )

    reason = models.TextField(
        blank=True,
        help_text=_("Reason for the role change")
    )

    class Meta:
        app_label = 'accounts'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['changed_by']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        old_role_name = self.old_role.display_name if self.old_role else "None"
        new_role_name = self.new_role.display_name if self.new_role else "None"
        return f"Role change for {self.user.email}: {old_role_name} → {new_role_name}"