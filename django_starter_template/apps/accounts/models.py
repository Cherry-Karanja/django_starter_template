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
from django_otp.plugins.otp_totp.models import TOTPDevice
import uuid
import pytz


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

    # Two-factor authentication
    otp_device = models.OneToOneField(
        TOTPDevice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='custom_user',
        help_text=_("TOTP device for two-factor authentication")
    )
    backup_codes = models.JSONField(
        null=True,
        blank=True,
        help_text=_("Backup codes for 2FA recovery")
    )

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
            return set(f"{perm['content_type__app_label']}.{perm['codename']}" 
                      for perm in Permission.objects.values('content_type__app_label', 'codename'))

        return set(f"{perm['content_type__app_label']}.{perm['codename']}" 
                  for perm in self.role.permissions.values('content_type__app_label', 'codename'))

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

    # Two-factor authentication methods
    def is_otp_enabled(self):
        """Check if user has 2FA enabled"""
        return self.otp_device is not None

    def enable_otp(self, device_name="default"):
        """Enable 2FA for the user"""
        if self.otp_device:
            return self.otp_device

        device = TOTPDevice.objects.create(
            user=self,
            name=device_name,
            confirmed=False
        )
        self.otp_device = device
        self.save(update_fields=['otp_device'])
        return device

    def disable_otp(self):
        """Disable 2FA for the user"""
        if self.otp_device:
            self.otp_device.delete()
            self.otp_device = None
            self.backup_codes = None
            self.save(update_fields=['otp_device', 'backup_codes'])

    def generate_backup_codes(self, count=10):
        """Generate backup codes for 2FA recovery"""
        import secrets
        codes = [secrets.token_hex(4).upper() for _ in range(count)]
        self.backup_codes = codes
        self.save(update_fields=['backup_codes'])
        return codes

    def verify_backup_code(self, code):
        """Verify and consume a backup code"""
        if not self.backup_codes or code not in self.backup_codes:
            return False

        self.backup_codes.remove(code)
        self.save(update_fields=['backup_codes'])
        return True

    def get_backup_codes_count(self):
        """Get the number of remaining backup codes"""
        return len(self.backup_codes) if self.backup_codes else 0

    # Role-based permission properties for compatibility with permissions.py
    @property
    def is_staff_member(self):
        """Check if user is a staff member or higher"""
        if not self.role or not self.role.is_active:
            return False
        return self.role.name in ['staff', 'manager', 'admin', 'super_admin']

    @property
    def is_supervisor_or_above(self):
        """Check if user is a supervisor (manager) or higher"""
        if not self.role or not self.role.is_active:
            return False
        return self.role.name in ['manager', 'admin', 'super_admin']

    @property
    def is_admin_or_above(self):
        """Check if user is an admin or higher"""
        if not self.role or not self.role.is_active:
            return False
        return self.role.name in ['admin', 'super_admin']


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
    device_info = models.JSONField(
        null=True,
        blank=True,
        help_text=_("Parsed device information from user agent")
    )

    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When this session was revoked (if applicable)")
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
            models.Index(fields=['revoked_at']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['last_activity']),
        ]

    def __str__(self):
        return f"Session for {self.user.email} from {self.ip_address}"

    def is_expired(self):
        """Check if session has expired based on Django session"""
        from django.contrib.sessions.models import Session
        try:
            django_session = Session.objects.get(session_key=self.session_key)
            # Handle timezone-aware or naive expire_date
            if timezone.is_naive(django_session.expire_date):
                expire_date_utc = timezone.make_aware(django_session.expire_date, timezone=pytz.UTC)
            else:
                expire_date_utc = django_session.expire_date
            # Compare with current time in UTC
            return expire_date_utc <= timezone.now()
        except Session.DoesNotExist:
            return True

    @property
    def is_active(self):
        """Check if session is active (not expired and not revoked)"""
        return not (self.revoked_at or self.is_expired())

    def update_activity(self):
        """Update last activity timestamp and sync expiration with Django session"""
        from django.contrib.sessions.models import Session
        try:
            django_session = Session.objects.get(session_key=self.session_key)
            UserSession.objects.filter(id=self.id).update(
                last_activity=timezone.now(),
                expires_at=django_session.expire_date
            )
        except Session.DoesNotExist:
            # If Django session doesn't exist, mark as inactive
            UserSession.objects.filter(id=self.id).update(is_active=False)

    def expire(self):
        """Mark session as expired"""
        # Since expiration is handled by is_expired(), this method is deprecated
        # But keep for compatibility
        pass

    def revoke(self, reason=None):
        """Revoke session with optional reason"""
        UserSession.objects.filter(id=self.id).update(revoked_at=timezone.now())
        # Could add reason to a field if needed in the future

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
        from .services import DeviceDetectionService, GeoIPService
        from django.contrib.sessions.models import Session
        
        session_key = request.session.session_key
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        device_info = DeviceDetectionService.parse_user_agent(user_agent)
        location_info = GeoIPService.get_location_info(ip_address)
        
        # Set expiration to 1 hour from now for session management
        session_expires_at = timezone.now() + timedelta(seconds=3600)
        
        # Ensure Django session also expires in 1 hour
        request.session.set_expiry(3600)
        
        # Check if session already exists (active or inactive)
        existing_session = cls.objects.filter(session_key=session_key).first()
        if existing_session:
            # Update existing session instead of creating new one
            existing_session.user = user
            existing_session.ip_address = ip_address
            existing_session.user_agent = user_agent
            existing_session.device_info = device_info
            existing_session.location_info = location_info
            existing_session.expires_at = session_expires_at
            existing_session.save()
            session = existing_session
        else:
            # Create new session
            session = cls.objects.create(
                user=user,
                session_key=session_key,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info,
                location_info=location_info,
                expires_at=session_expires_at
            )
        
        return session

    def calculate_risk_score(self):
        """
        Calculate a risk score for this session based on various factors
        
        Returns an integer score from 0-100 where higher scores indicate higher risk
        """
        score = 0
        
        # Factor 1: New device (30 points)
        if self.device_info:
            user_sessions = UserSession.objects.filter(
                user=self.user,
                device_info__isnull=False
            ).exclude(id=self.id)
            
            device_known = any(
                session.device_info.get('device_brand') == self.device_info.get('device_brand') and
                session.device_info.get('device_model') == self.device_info.get('device_model')
                for session in user_sessions if session.device_info
            )
            
            if not device_known:
                score += 30
        
        # Factor 2: New location (25 points)
        if self.location_info:
            user_sessions = UserSession.objects.filter(
                user=self.user,
                location_info__isnull=False
            ).exclude(id=self.id)
            
            location_known = any(
                session.location_info.get('country_code') == self.location_info.get('country_code') and
                session.location_info.get('city') == self.location_info.get('city')
                for session in user_sessions if session.location_info
            )
            
            if not location_known:
                score += 25
        
        # Factor 3: Unusual login time (15 points)
        # Consider login between 2 AM and 6 AM as higher risk
        login_hour = self.created_at.hour
        if 2 <= login_hour <= 6:
            score += 15
        
        # Factor 4: Bot-like user agent (20 points)
        if self.device_info and self.device_info.get('is_bot'):
            score += 20
        
        # Factor 5: Multiple failed login attempts recently (10 points)
        from .models import LoginAttempt
        recent_failures = LoginAttempt.objects.filter(
            email=self.user.email,
            success=False,
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).count()
        
        if recent_failures > 3:
            score += 10
        
        # Ensure score doesn't exceed 100
        return min(score, 100)

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

    @property
    def risk_score(self):
        """
        Calculate a risk score for this session based on various factors.
        Returns a float between 0.0 (low risk) and 1.0 (high risk).
        """
        score = 0.0
        
        # Check if session is expired
        if self.is_expired:
            score += 0.3
        
        # Check if session is inactive
        if not self.is_active:
            score += 0.2
        
        # Check for suspicious location (simplified)
        # In production, you'd compare with user's known locations
        if self.location_info:
            score += 0.1  # Slightly suspicious if we have location data
        
        # Check device/browser consistency
        # This is a basic check - in production you'd have more sophisticated logic
        if not self.device_type or not self.browser:
            score += 0.1
        
        # Cap at 1.0
        return min(score, 1.0)


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