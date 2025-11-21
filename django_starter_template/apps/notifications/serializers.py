from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from .models import (
    NotificationTemplate,
    Notification,
    NotificationDelivery,
    NotificationPreference,
    NotificationEvent
)


class NotificationTemplateSerializer(serializers.ModelSerializer):
    """Serializer for notification templates"""

    class Meta:
        model = NotificationTemplate
        fields = [
            'id', 'name', 'description', 'template_type', 'subject',
            'body', 'variables', 'priority', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_variables(self, value):
        """Validate that variables is a valid JSON schema"""
        if not isinstance(value, dict):
            raise serializers.ValidationError(_("Variables must be a valid JSON object"))
        return value


class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for notifications"""

    recipient_username = serializers.CharField(source='recipient.get_username', read_only=True)
    recipient_email = serializers.EmailField(source='recipient.email', read_only=True)
    template_name = serializers.CharField(source='template.name', read_only=True)
    template_type = serializers.CharField(source='template.template_type', read_only=True)

    class Meta:
        model = Notification
        fields = [
            'id', 'recipient', 'recipient_username', 'recipient_email',
            'template', 'template_name', 'template_type',
            'subject', 'body', 'data', 'status', 'priority',
            'scheduled_at', 'sent_at', 'delivered_at',
            'content_type', 'object_id', 'related_url',
            'retry_count', 'max_retries', 'last_error',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'recipient_username', 'recipient_email',
            'template_name', 'template_type', 'sent_at', 'delivered_at',
            'retry_count', 'created_at', 'updated_at'
        ]

    def validate_scheduled_at(self, value):
        """Validate scheduled time is in the future"""
        from django.utils import timezone
        if value and value <= timezone.now():
            raise serializers.ValidationError(_("Scheduled time must be in the future"))
        return value


class NotificationDeliverySerializer(serializers.ModelSerializer):
    """Serializer for notification deliveries"""

    notification_subject = serializers.CharField(source='notification.subject', read_only=True)

    class Meta:
        model = NotificationDelivery
        fields = [
            'id', 'notification', 'notification_subject', 'delivery_method',
            'status', 'provider', 'provider_message_id', 'recipient_address',
            'sent_at', 'delivered_at', 'error_message', 'retry_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'notification_subject', 'sent_at', 'delivered_at',
            'created_at', 'updated_at'
        ]


class NotificationPreferenceSerializer(serializers.ModelSerializer):
    """Serializer for notification preferences"""

    user_username = serializers.CharField(source='user.get_username', read_only=True)
    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = NotificationPreference
        fields = [
            'id', 'user', 'user_username', 'user_email',
            'email_enabled', 'sms_enabled', 'push_enabled', 'in_app_enabled',
            'exam_notifications', 'moderation_notifications',
            'system_notifications', 'deadline_notifications',
            'quiet_hours_start', 'quiet_hours_end',
            'email_address', 'phone_number', 'device_tokens',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'user_username', 'user_email', 'created_at', 'updated_at']

    def validate_device_tokens(self, value):
        """Validate device tokens is a list"""
        if not isinstance(value, list):
            raise serializers.ValidationError(_("Device tokens must be a list"))
        return value


class NotificationEventSerializer(serializers.ModelSerializer):
    """Serializer for notification events"""

    default_email_template_name = serializers.CharField(
        source='default_email_template.name', read_only=True
    )
    default_sms_template_name = serializers.CharField(
        source='default_sms_template.name', read_only=True
    )
    default_push_template_name = serializers.CharField(
        source='default_push_template.name', read_only=True
    )
    default_in_app_template_name = serializers.CharField(
        source='default_in_app_template.name', read_only=True
    )

    class Meta:
        model = NotificationEvent
        fields = [
            'id', 'event_type', 'name', 'description',
            'default_email_template', 'default_email_template_name',
            'default_sms_template', 'default_sms_template_name',
            'default_push_template', 'default_push_template_name',
            'default_in_app_template', 'default_in_app_template_name',
            'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class SendNotificationSerializer(serializers.Serializer):
    """Serializer for sending notifications"""

    recipient_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text=_("List of user IDs to send notification to")
    )
    template_id = serializers.UUIDField(
        help_text=_("ID of the notification template to use")
    )
    data = serializers.DictField(
        default=dict,
        help_text=_("Template variables and additional data")
    )
    scheduled_at = serializers.DateTimeField(
        required=False,
        help_text=_("When to send the notification (optional)")
    )
    priority = serializers.ChoiceField(
        choices=['low', 'medium', 'high', 'urgent'],
        default='medium',
        help_text=_("Priority level of the notification")
    )

    def validate_recipient_ids(self, value):
        """Validate recipient IDs exist"""
        from django.contrib.auth import get_user_model
        User = get_user_model()
        existing_ids = set(User.objects.filter(id__in=value).values_list('id', flat=True))
        missing_ids = set(value) - existing_ids
        if missing_ids:
            raise serializers.ValidationError(
                _("Users with IDs {} do not exist").format(list(missing_ids))
            )
        return value

    def validate_template_id(self, value):
        """Validate template exists and is active"""
        try:
            template = NotificationTemplate.objects.get(id=value, is_active=True)
        except NotificationTemplate.DoesNotExist:
            raise serializers.ValidationError(_("Template does not exist or is not active"))
        except ValueError:
            raise serializers.ValidationError(_("Invalid template ID format"))
        return value

    def validate_scheduled_at(self, value):
        """Validate scheduled time is in the future"""
        from django.utils import timezone
        if value and value <= timezone.now():
            raise serializers.ValidationError(_("Scheduled time must be in the future"))
        return value


class BulkNotificationSerializer(serializers.Serializer):
    """Serializer for bulk notification operations"""

    notification_ids = serializers.ListField(
        child=serializers.UUIDField(),
        help_text=_("List of notification IDs")
    )
    action = serializers.ChoiceField(
        choices=['cancel', 'retry', 'mark_delivered'],
        help_text=_("Action to perform on the notifications")
    )

    def validate_notification_ids(self, value):
        """Validate notification IDs exist"""
        try:
            existing_ids = set(Notification.objects.filter(id__in=value).values_list('id', flat=True))
            missing_ids = set(value) - existing_ids
            if missing_ids:
                raise serializers.ValidationError(
                    _("Notifications with IDs {} do not exist").format(list(missing_ids))
                )
        except (ValueError, TypeError):
            raise serializers.ValidationError(_("Invalid notification ID format"))
        return value


class SendNotificationSerializer(serializers.Serializer):
    """Serializer for sending notifications"""
    template_id = serializers.IntegerField(help_text="ID of the notification template to use")
    recipient_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="List of user IDs to send notifications to"
    )
    subject = serializers.CharField(required=False, allow_blank=True, help_text="Custom subject (optional, overrides template)")
    data = serializers.DictField(required=False, help_text="Template variables data")
    scheduled_at = serializers.DateTimeField(required=False, help_text="Schedule notification for later (ISO 8601 format)")
    priority = serializers.ChoiceField(
        choices=['low', 'medium', 'high', 'urgent'],
        required=False,
        help_text="Notification priority"
    )


class MarkNotificationsReadSerializer(serializers.Serializer):
    """Serializer for marking notifications as read"""
    notification_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="List of notification IDs to mark as read"
    )