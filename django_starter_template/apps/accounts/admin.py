"""
Admin interface for the accounts app
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from django.contrib import messages
from .models import User, UserRole, UserProfile, LoginAttempt, UserSession, UserRoleHistory
from apps.core.services import TwoFactorAuthService


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom admin interface for the User model"""

    # Fields to display in the user list
    list_display = ('email', 'full_name', 'employee_id', 'role_badge', 'status_badges', 'security_status', 'two_factor_status', 'login_info', 'created_at_display')
    list_filter = ('role', 'is_approved', 'is_verified', 'is_active', 'is_staff', 'is_superuser',
                   'account_locked_until', 'must_change_password', 'created_at', 'last_login')
    search_fields = ('email', 'first_name', 'last_name', 'employee_id')
    ordering = ('-created_at',)
    actions = ['approve_users', 'reject_users', 'activate_users', 'deactivate_users',
               'unlock_accounts', 'require_password_change', 'enable_2fa', 'disable_2fa']

    # Fieldsets for the user detail/edit page
    fieldsets = (
        (None, {'fields': ('email', 'password','first_name', 'last_name')}),
        (_('Role & Status'), {
            'fields': ('role', 'employee_id', 'is_approved', 'is_verified'),
        }),
        (_('Security'), {
            'fields': ('failed_login_attempts', 'account_locked_until', 'must_change_password'),
        }),
        (_('System Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {
            'fields': ('last_login', 'created_at', 'password_changed_at'),
        }),
    )

    # Fieldsets for creating new users
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'first_name', 'last_name', 'role'),
        }),
    )

    # Make some fields readonly
    readonly_fields = ('created_at', 'last_login', 'password_changed_at')

    # Filter horizontal for many-to-many fields
    filter_horizontal = ('groups', 'user_permissions')

    def role_badge(self, obj):
        """Display user role as a colored badge"""
        if not obj.role:
            return format_html('<span style="background-color: #6c757d; color: white; padding: 3px 7px; border-radius: 3px; font-size: 0.8em;">No Role</span>')

        role_colors = {
            'admin': '#007bff',
            'moderator': '#28a745',
            'user': '#ffc107',
            'staff': '#dc3545',
        }

        color = role_colors.get(obj.role.name.lower(), '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 7px; border-radius: 3px; font-size: 0.8em;">{}</span>',
            color, obj.role.name
        )
    role_badge.short_description = 'Role'

    def status_badges(self, obj):
        """Display approval and verification status as badges"""
        badges = []

        if obj.is_approved:
            badges.append('<span style="background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.75em; margin-right: 3px;">Approved</span>')
        else:
            badges.append('<span style="background-color: #ffc107; color: black; padding: 2px 6px; border-radius: 3px; font-size: 0.75em; margin-right: 3px;">Pending</span>')

        if obj.is_verified:
            badges.append('<span style="background-color: #007bff; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.75em;">Verified</span>')
        else:
            badges.append('<span style="background-color: #6c757d; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.75em;">Unverified</span>')

        return format_html(''.join(badges))
    status_badges.short_description = 'Status'

    def security_status(self, obj):
        """Display security status indicators"""
        indicators = []

        if obj.account_locked_until and obj.account_locked_until > timezone.now():
            indicators.append('<span style="color: #dc3545; font-weight: bold;" title="Account Locked">🔒</span>')
        elif obj.failed_login_attempts > 0:
            indicators.append(f'<span style="color: #ffc107;" title="{obj.failed_login_attempts} failed attempts">⚠️</span>')

        if obj.must_change_password:
            indicators.append('<span style="color: #007bff;" title="Password change required">🔑</span>')

        if not indicators:
            indicators.append('<span style="color: #28a745;" title="Secure">✅</span>')

        return format_html(' '.join(indicators))
    security_status.short_description = 'Security'

    def two_factor_status(self, obj):
        """Display 2FA status"""
        if obj.is_otp_enabled():
            return format_html('<span style="color: #28a745;">✓ Enabled</span>')
        else:
            return format_html('<span style="color: #dc3545;">✗ Disabled</span>')
    two_factor_status.short_description = '2FA'

    def login_info(self, obj):
        """Display last login information"""
        if obj.last_login:
            days_since = (timezone.now() - obj.last_login).days
            if days_since == 0:
                return format_html('<span style="color: #28a745;">Today</span>')
            elif days_since == 1:
                return format_html('<span style="color: #007bff;">Yesterday</span>')
            elif days_since < 7:
                return format_html('<span style="color: #ffc107;">{} days ago</span>', days_since)
            else:
                return format_html('<span style="color: #dc3545;">{} days ago</span>', days_since)
        return format_html('<span style="color: #6c757d;">Never</span>')
    login_info.short_description = 'Last Login'

    def full_name(self, obj):
        """Display user's full name"""
        if obj.first_name or obj.last_name:
            return f"{obj.first_name} {obj.last_name}".strip()
        return obj.email
    full_name.short_description = 'Name'

    def created_at_display(self, obj):
        """Display created timestamp in configured timezone"""
        if obj.created_at:
            # Convert to configured timezone
            from django.conf import settings
            import pytz
            tz = pytz.timezone(settings.TIME_ZONE)
            local_time = obj.created_at.astimezone(tz)
            return local_time.strftime('%Y-%m-%d %H:%M:%S %Z')
        return '-'
    created_at_display.short_description = 'Created'
    created_at_display.admin_order_field = 'created_at'
    # Bulk Actions
    def approve_users(self, request, queryset):
        """Bulk approve selected users"""
        updated = queryset.update(is_approved=True)
        self.message_user(request, f"{updated} users have been approved.")
    approve_users.short_description = "Approve selected users"

    def reject_users(self, request, queryset):
        """Bulk reject selected users"""
        updated = queryset.update(is_approved=False)
        self.message_user(request, f"{updated} users have been rejected.")
    reject_users.short_description = "Reject selected users"

    def activate_users(self, request, queryset):
        """Bulk activate selected users"""
        updated = queryset.update(is_active=True)
        self.message_user(request, f"{updated} users have been activated.")
    activate_users.short_description = "Activate selected users"

    def deactivate_users(self, request, queryset):
        """Bulk deactivate selected users"""
        updated = queryset.update(is_active=False)
        self.message_user(request, f"{updated} users have been deactivated.")
    deactivate_users.short_description = "Deactivate selected users"

    def unlock_accounts(self, request, queryset):
        """Bulk unlock selected user accounts"""
        updated = queryset.filter(account_locked_until__isnull=False).update(
            account_locked_until=None,
            failed_login_attempts=0
        )
        self.message_user(request, f"{updated} user accounts have been unlocked.")
    unlock_accounts.short_description = "Unlock selected accounts"

    def require_password_change(self, request, queryset):
        """Bulk require password change for selected users"""
        updated = queryset.update(must_change_password=True)
        self.message_user(request, f"{updated} users will be required to change their password on next login.")
    require_password_change.short_description = "Require password change"

    def enable_2fa(self, request, queryset):
        """Bulk enable 2FA for selected users"""
        enabled_count = 0
        for user in queryset:
            try:
                TwoFactorAuthService.setup_2fa(user)
                enabled_count += 1
            except Exception as e:
                self.message_user(request, f"Failed to enable 2FA for {user.email}: {str(e)}", level=messages.ERROR)
        self.message_user(request, f"2FA enabled for {enabled_count} users.")
    enable_2fa.short_description = "Enable 2FA for selected users"

    def disable_2fa(self, request, queryset):
        """Bulk disable 2FA for selected users"""
        disabled_count = 0
        for user in queryset:
            try:
                TwoFactorAuthService.disable_2fa(user)
                disabled_count += 1
            except Exception as e:
                self.message_user(request, f"Failed to disable 2FA for {user.email}: {str(e)}", level=messages.ERROR)
        self.message_user(request, f"2FA disabled for {disabled_count} users.")
    disable_2fa.short_description = "Disable 2FA for selected users"


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    """Admin interface for UserRole model"""

    list_display = ('name', 'description', 'user_count', 'status_badge', 'permission_count', 'created_at_display')
    list_filter = ('is_active', 'created_at', 'permissions')
    search_fields = ('name', 'description')
    filter_horizontal = ('permissions',)
    ordering = ('name',)
    actions = ['activate_roles', 'deactivate_roles']

    fieldsets = (
        (None, {'fields': ('name', 'description', 'is_active', 'display_name')}),
        (_('Permissions'), {
            'fields': ('permissions',),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at',),
            'classes': ('collapse',)
        }),
    )

    readonly_fields = ('created_at',)

    def status_badge(self, obj):
        """Display active status as a colored badge"""
        if obj.is_active:
            return format_html('<span style="background-color: #28a745; color: white; padding: 3px 7px; border-radius: 3px;">Active</span>')
        else:
            return format_html('<span style="background-color: #dc3545; color: white; padding: 3px 7px; border-radius: 3px;">Inactive</span>')
    status_badge.short_description = 'Status'

    def user_count(self, obj):
        """Display count of users with this role"""
        count = obj.users.filter(is_active=True).count()
        return format_html('<a href="{}?role__id__exact={}">{}</a>', reverse('admin:accounts_user_changelist'), obj.id, count)
    user_count.short_description = 'Users'

    def permission_count(self, obj):
        """Display count of permissions assigned to this role"""
        count = obj.permissions.count()
        return count
    permission_count.short_description = 'Permissions'

    def created_at_display(self, obj):
        """Display created timestamp in configured timezone"""
        if obj.created_at:
            # Convert to configured timezone
            from django.conf import settings
            import pytz
            tz = pytz.timezone(settings.TIME_ZONE)
            local_time = obj.created_at.astimezone(tz)
            return local_time.strftime('%Y-%m-%d %H:%M:%S %Z')
        return '-'
    created_at_display.short_description = 'Created'
    created_at_display.admin_order_field = 'created_at'

    def activate_roles(self, request, queryset):
        """Bulk activate selected roles"""
        updated = queryset.update(is_active=True)
        self.message_user(request, f"{updated} roles have been activated.")
    activate_roles.short_description = "Activate selected roles"

    def deactivate_roles(self, request, queryset):
        """Bulk deactivate selected roles"""
        updated = queryset.update(is_active=False)
        self.message_user(request, f"{updated} roles have been deactivated.")
    deactivate_roles.short_description = "Deactivate selected roles"


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin interface for UserProfile model"""

    list_display = ('user_link', 'bio_preview', 'preferred_language', 'interface_theme', 'last_activity', 'created_at_display')
    list_filter = ('preferred_language', 'interface_theme', 'allow_notifications', 'created_at')
    search_fields = ('user__email', 'user__first_name', 'user__last_name', 'bio')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')

    fieldsets = (
        (None, {'fields': ('user', 'bio', 'preferred_language')}),
        (_('Privacy Settings'), {
            'fields': ('show_email', 'show_phone', 'allow_notifications'),
        }),
        (_('System Preferences'), {
            'fields': ('interface_theme', 'notification_preferences'),
            'classes': ('collapse',),
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )

    def user_link(self, obj):
        """Link to the user in admin"""
        url = reverse('admin:accounts_user_change', args=[obj.user.id])
        return format_html('<a href="{}">{}</a>', url, obj.user.get_full_name() or obj.user.email)
    user_link.short_description = 'User'

    def bio_preview(self, obj):
        """Display a preview of the bio"""
        if obj.bio:
            preview = obj.bio[:50] + '...' if len(obj.bio) > 50 else obj.bio
            return preview
        return '-'
    bio_preview.short_description = 'Bio'

    def last_activity(self, obj):
        """Display last activity from user"""
        if obj.user.last_login:
            days_since = (timezone.now() - obj.user.last_login).days
            if days_since == 0:
                return format_html('<span style="color: #28a745;">Today</span>')
            elif days_since == 1:
                return format_html('<span style="color: #007bff;">Yesterday</span>')
            elif days_since < 7:
                return format_html('<span style="color: #ffc107;">{} days ago</span>', days_since)
            else:
                return format_html('<span style="color: #dc3545;">{} days ago</span>', days_since)
        return format_html('<span style="color: #6c757d;">Never</span>')
    last_activity.short_description = 'Last Activity'

    def created_at_display(self, obj):
        """Display created timestamp in configured timezone"""
        if obj.created_at:
            # Convert to configured timezone
            from django.conf import settings
            import pytz
            tz = pytz.timezone(settings.TIME_ZONE)
            local_time = obj.created_at.astimezone(tz)
            return local_time.strftime('%Y-%m-%d %H:%M:%S %Z')
        return '-'
    created_at_display.short_description = 'Created'
    created_at_display.admin_order_field = 'created_at'


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    """Admin interface for tracking login attempts"""

    list_display = ('email', 'user_link', 'ip_address', 'success_badge', 'device_info', 'failure_reason_display', 'created_at_display')
    list_filter = ('success', 'device_type', 'created_at', 'failure_reason', 'device_os', 'browser')
    search_fields = ('email', 'ip_address', 'user__email', 'user_agent')
    readonly_fields = ('user', 'email', 'ip_address', 'success', 'user_agent', 'failure_reason', 'location_info',
                      'device_type', 'device_os', 'browser', 'session_id', 'created_at', 'updated_at')
    ordering = ('-created_at',)

    fieldsets = (
        (None, {'fields': ('user', 'email', 'created_at')}),
        (_('Authentication Info'), {
            'fields': ('success', 'failure_reason', 'session_id'),
        }),
        (_('Client Info'), {
            'fields': ('ip_address', 'device_type', 'device_os', 'browser'),
        }),
        (_('Location Data'), {
            'fields': ('location_info',),
        }),
        (_('Full User Agent'), {
            'fields': ('user_agent',),
            'classes': ('collapse',),
        }),
    )

    def failure_reason_display(self, obj):
        """Display failure reason as a colored badge"""
        if obj.success:
            return format_html('<span style="color: #28a745;">Success</span>')

        if not obj.failure_reason:
            return format_html('<span style="color: #6c757d;">Unknown</span>')

        reason_colors = {
            'invalid_credentials': '#dc3545',
            'account_locked': '#ffc107',
            'account_inactive': '#6c757d',
            'too_many_attempts': '#dc3545',
            'invalid_token': '#dc3545',
        }

        color = reason_colors.get(obj.failure_reason, '#dc3545')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8em;">{}</span>',
            color, obj.failure_reason.replace('_', ' ').title()
        )
    failure_reason_display.short_description = 'Failure Reason'

    def success_badge(self, obj):
        """Display success status as a colored badge"""
        if obj.success:
            return format_html('<span style="background-color: #28a745; color: white; padding: 3px 7px; border-radius: 3px;">Success</span>')
        else:
            return format_html('<span style="background-color: #dc3545; color: white; padding: 3px 7px; border-radius: 3px;">Failed</span>')
    success_badge.short_description = 'Status'

    def user_link(self, obj):
        """Link to the user in admin if it exists"""
        if obj.user:
            url = reverse('admin:accounts_user_change', args=[obj.user.id])
            return format_html('<a href="{}">{}</a>', url, obj.user.email)
        return '-'
    user_link.short_description = 'User'

    def device_info(self, obj):
        """Format device info nicely"""
        if obj.device_type and obj.browser:
            return f"{obj.device_type} / {obj.browser}"
        return obj.device_type or '-'
    device_info.short_description = 'Device'

    def created_at_display(self, obj):
        """Display created timestamp in configured timezone"""
        if obj.created_at:
            # Convert to configured timezone
            from django.conf import settings
            import pytz
            tz = pytz.timezone(settings.TIME_ZONE)
            local_time = obj.created_at.astimezone(tz)
            return local_time.strftime('%Y-%m-%d %H:%M:%S %Z')
        return '-'
    created_at_display.short_description = 'Created'
    created_at_display.admin_order_field = 'created_at'


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """Admin interface for user session tracking"""

    list_display = ('id', 'user_link', 'status_badge', 'device_info', 'last_activity_display', 'expires_at_display')
    list_filter = ('revoked_at', 'device_type', 'created_at')
    search_fields = ('user__email', 'ip_address', 'session_key', 'device_type')
    readonly_fields = ('user', 'session_key', 'ip_address', 'user_agent', 'revoked_at', 'device_type',
                      'device_os', 'browser', 'location_info', 'last_activity', 'expires_at', 'created_at', 'updated_at')
    ordering = ('-last_activity',)
    actions = ['revoke_sessions']

    fieldsets = (
        (None, {'fields': ( 'user', 'session_key', 'revoked_at')}),
        (_('Session Info'), {
            'fields': ('last_activity', 'expires_at'),
        }),
        (_('Client Info'), {
            'fields': ('ip_address', 'device_type', 'device_os', 'browser'),
        }),
        (_('Location Data'), {
            'fields': ('location_info',),
        }),
        (_('Full User Agent'), {
            'fields': ('user_agent',),
            'classes': ('collapse',),
        }),
    )



    def user_link(self, obj):
        """Link to the user in admin"""
        url = reverse('admin:accounts_user_change', args=[obj.user.id])
        return format_html('<a href="{}">{}</a>', url, obj.user.email)
    user_link.short_description = 'User'

    def device_info(self, obj):
        """Format device info nicely"""
        if obj.device_type and obj.browser:
            return f"{obj.device_type} / {obj.browser}"
        return obj.device_type or '-'
    device_info.short_description = 'Device'

    def last_activity_display(self, obj):
        """Display last activity timestamp in configured timezone"""
        if obj.last_activity:
            # Convert to configured timezone
            from django.conf import settings
            import pytz
            tz = pytz.timezone(settings.TIME_ZONE)
            local_time = obj.last_activity.astimezone(tz)
            return local_time.strftime('%Y-%m-%d %H:%M:%S %Z')
        return '-'
    last_activity_display.short_description = 'Last Activity'
    last_activity_display.admin_order_field = 'last_activity'

    def expires_at_display(self, obj):
        """Display expiration timestamp in configured timezone"""
        if obj.expires_at:
            # Convert to configured timezone
            from django.conf import settings
            import pytz
            tz = pytz.timezone(settings.TIME_ZONE)
            local_time = obj.expires_at.astimezone(tz)
            return local_time.strftime('%Y-%m-%d %H:%M:%S %Z')
        return '-'
    expires_at_display.short_description = 'Expires At'
    expires_at_display.admin_order_field = 'expires_at'

    def status_badge(self, obj):
        """Display active status as a colored badge"""
        if obj.revoked_at:
            return format_html('<span style="background-color: #dc3545; color: white; padding: 3px 7px; border-radius: 3px;">Revoked</span>')
        elif obj.is_expired():
            return format_html('<span style="background-color: #6c757d; color: white; padding: 3px 7px; border-radius: 3px;">Expired</span>')
        else:
            return format_html('<span style="background-color: #28a745; color: white; padding: 3px 7px; border-radius: 3px;">Active</span>')
    status_badge.short_description = 'Status'

    def revoke_sessions(self, request, queryset):
        """Admin action to revoke selected sessions"""
        from django.utils import timezone
        for session in queryset:
            if not session.revoked_at:
                session.revoke(revoked_by=request.user, reason='admin_action')

        self.message_user(request, f"{queryset.count()} sessions have been revoked.")
    revoke_sessions.short_description = "Revoke selected sessions"


@admin.register(UserRoleHistory)
class UserRoleHistoryAdmin(admin.ModelAdmin):
    """Admin interface for UserRoleHistory model"""

    list_display = ('user_link', 'role_change_display', 'changed_by_link', 'reason_badge', 'created_at_display')
    list_filter = ('old_role', 'new_role', 'changed_by', 'created_at')
    search_fields = ('user__email', 'user__first_name', 'user__last_name', 'reason', 'old_role__name', 'new_role__name')
    readonly_fields = ('user', 'old_role', 'new_role', 'changed_by', 'reason', 'created_at')
    ordering = ('-created_at',)

    fieldsets = (
        (None, {'fields': ('user', 'created_at')}),
        (_('Role Change'), {
            'fields': ('old_role', 'new_role'),
        }),
        (_('Change Details'), {
            'fields': ('changed_by', 'reason'),
        }),
    )

    def user_link(self, obj):
        """Link to the user who had their role changed"""
        if obj.user:
            url = reverse('admin:accounts_user_change', args=[obj.user.id])
            return format_html('<a href="{}">{}</a>', url, obj.user.email)
        return '-'
    user_link.short_description = 'User'

    def changed_by_link(self, obj):
        """Link to the user who made the change"""
        if obj.changed_by:
            url = reverse('admin:accounts_user_change', args=[obj.changed_by.id])
            return format_html('<a href="{}">{}</a>', url, obj.changed_by.email)
        return 'System'
    changed_by_link.short_description = 'Changed By'

    def role_change_display(self, obj):
        """Display role change with visual indicators"""
        old_role = obj.old_role.name if obj.old_role else 'None'
        new_role = obj.new_role.name if obj.new_role else 'None'

        if obj.old_role and obj.new_role:
            # Role change
            html = f"""
            <div style="font-size: 0.9em;">
                <span style="color: #dc3545;">{old_role}</span>
                <span style="margin: 0 5px;">→</span>
                <span style="color: #28a745;">{new_role}</span>
            </div>
            """
        elif obj.new_role:
            # Role assigned
            html = f"""
            <div style="font-size: 0.9em;">
                <span style="color: #6c757d;">None</span>
                <span style="margin: 0 5px;">→</span>
                <span style="color: #28a745;">{new_role}</span>
            </div>
            """
        else:
            # Role removed
            html = f"""
            <div style="font-size: 0.9em;">
                <span style="color: #dc3545;">{old_role}</span>
                <span style="margin: 0 5px;">→</span>
                <span style="color: #6c757d;">None</span>
            </div>
            """

        return format_html(html)
    role_change_display.short_description = 'Role Change'

    def reason_badge(self, obj):
        """Display reason as a colored badge"""
        if not obj.reason:
            return format_html('<span style="background-color: #6c757d; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8em;">No Reason</span>')

        # Common reasons and their colors
        reason_colors = {
            'promotion': '#28a745',
            'demotion': '#dc3545',
            'transfer': '#007bff',
            'termination': '#dc3545',
            'contract_change': '#ffc107',
            'system_assignment': '#6c757d',
            'role_update': '#17a2b8',
        }

        # Try to match common patterns
        reason_lower = obj.reason.lower()
        color = '#6c757d'  # Default gray

        for key, col in reason_colors.items():
            if key in reason_lower:
                color = col
                break

        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8em;">{}</span>',
            color, obj.reason[:20] + ('...' if len(obj.reason) > 20 else '')
        )
    reason_badge.short_description = 'Reason'

    def created_at_display(self, obj):
        """Display created timestamp in configured timezone"""
        if obj.created_at:
            # Convert to configured timezone
            from django.conf import settings
            import pytz
            tz = pytz.timezone(settings.TIME_ZONE)
            local_time = obj.created_at.astimezone(tz)
            return local_time.strftime('%Y-%m-%d %H:%M:%S %Z')
        return '-'
    created_at_display.short_description = 'Created'
    created_at_display.admin_order_field = 'created_at'