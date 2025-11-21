from django.db import models
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator
from apps.core.models import BaseModel

User = get_user_model()


class NotificationTemplate(BaseModel):
    """Templates for different types of notifications"""

    # Template types
    TYPE_EMAIL = 'email'
    TYPE_SMS = 'sms'
    TYPE_PUSH = 'push'
    TYPE_IN_APP = 'in_app'

    TEMPLATE_TYPES = [
        (TYPE_EMAIL, _('Email')),
        (TYPE_SMS, _('SMS')),
        (TYPE_PUSH, _('Push Notification')),
        (TYPE_IN_APP, _('In-App Notification')),
    ]

    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    template_type = models.CharField(max_length=20, choices=TEMPLATE_TYPES)
    subject = models.CharField(max_length=255, blank=True)  # For email
    body = models.TextField()
    is_active = models.BooleanField(default=True)

    # Template variables (JSON schema for validation)
    variables = models.JSONField(
        default=dict,
        help_text=_("JSON schema defining required template variables")
    )

    # Priority levels
    PRIORITY_LOW = 'low'
    PRIORITY_MEDIUM = 'medium'
    PRIORITY_HIGH = 'high'
    PRIORITY_URGENT = 'urgent'

    PRIORITY_CHOICES = [
        (PRIORITY_LOW, _('Low')),
        (PRIORITY_MEDIUM, _('Medium')),
        (PRIORITY_HIGH, _('High')),
        (PRIORITY_URGENT, _('Urgent')),
    ]

    priority = models.CharField(
        max_length=10,
        choices=PRIORITY_CHOICES,
        default=PRIORITY_MEDIUM
    )

    class Meta:
        app_label = 'notifications'
        verbose_name = _('Notification Template')
        verbose_name_plural = _('Notification Templates')

    def __str__(self):
        return f"{self.name} ({self.template_type})"


class Notification(BaseModel):
    """Individual notification instances"""

    # Status constants
    STATUS_PENDING = 'pending'
    STATUS_SENT = 'sent'
    STATUS_DELIVERED = 'delivered'
    STATUS_FAILED = 'failed'
    STATUS_CANCELLED = 'cancelled'

    STATUS_CHOICES = [
        (STATUS_PENDING, _('Pending')),
        (STATUS_SENT, _('Sent')),
        (STATUS_DELIVERED, _('Delivered')),
        (STATUS_FAILED, _('Failed')),
        (STATUS_CANCELLED, _('Cancelled')),
    ]

    recipient = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    template = models.ForeignKey(
        NotificationTemplate,
        on_delete=models.CASCADE,
        related_name='notifications'
    )

    # Notification content
    subject = models.CharField(max_length=255, blank=True)
    body = models.TextField()
    data = models.JSONField(
        default=dict,
        help_text=_("Template variables and additional data")
    )

    # Status and scheduling
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING
    )
    priority = models.CharField(
        max_length=10,
        choices=[
            ('low', _('Low')),
            ('medium', _('Medium')),
            ('high', _('High')),
            ('urgent', _('Urgent')),
        ],
        default='medium'
    )

    # Scheduling
    scheduled_at = models.DateTimeField(null=True, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    # Related objects (for linking notifications to specific entities)
    content_type = models.CharField(max_length=100, blank=True)  # e.g., 'exam', 'moderation_session'
    object_id = models.CharField(max_length=36, null=True, blank=True)  # UUID as string
    related_url = models.URLField(blank=True)

    # Retry and error handling
    retry_count = models.PositiveIntegerField(default=0)
    max_retries = models.PositiveIntegerField(default=3)
    last_error = models.TextField(blank=True)

    class Meta:
        app_label = 'notifications'
        ordering = ['-created_at']
        verbose_name = _('Notification')
        verbose_name_plural = _('Notifications')
        indexes = [
            models.Index(fields=['recipient', 'status']),
            models.Index(fields=['status', 'priority']),
            models.Index(fields=['scheduled_at']),
        ]

    def __str__(self):
        return f"Notification to {self.recipient} - {self.template.name}"


class NotificationDelivery(BaseModel):
    """Tracks delivery attempts for notifications"""

    # Delivery methods
    DELIVERY_EMAIL = 'email'
    DELIVERY_SMS = 'sms'
    DELIVERY_PUSH = 'push'
    DELIVERY_IN_APP = 'in_app'

    DELIVERY_METHOD_CHOICES = [
        (DELIVERY_EMAIL, _('Email')),
        (DELIVERY_SMS, _('SMS')),
        (DELIVERY_PUSH, _('Push')),
        (DELIVERY_IN_APP, _('In-App')),
    ]

    # Delivery status
    STATUS_PENDING = 'pending'
    STATUS_SENT = 'sent'
    STATUS_DELIVERED = 'delivered'
    STATUS_FAILED = 'failed'
    STATUS_BOUNCED = 'bounced'

    STATUS_CHOICES = [
        (STATUS_PENDING, _('Pending')),
        (STATUS_SENT, _('Sent')),
        (STATUS_DELIVERED, _('Delivered')),
        (STATUS_FAILED, _('Failed')),
        (STATUS_BOUNCED, _('Bounced')),
    ]

    notification = models.ForeignKey(
        Notification,
        on_delete=models.CASCADE,
        related_name='deliveries'
    )

    # Delivery method and status
    delivery_method = models.CharField(
        max_length=20,
        choices=DELIVERY_METHOD_CHOICES
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING
    )

    # Delivery details
    provider = models.CharField(max_length=100, blank=True)  # e.g., 'sendgrid', 'twilio'
    provider_message_id = models.CharField(max_length=255, blank=True)
    recipient_address = models.CharField(max_length=255)  # email, phone, device token

    # Timing
    sent_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    # Error handling
    error_message = models.TextField(blank=True)
    retry_count = models.PositiveIntegerField(default=0)

    class Meta:
        app_label = 'notifications'
        ordering = ['-created_at']
        verbose_name = _('Notification Delivery')
        verbose_name_plural = _('Notification Deliveries')
        unique_together = ['notification', 'delivery_method']

    def __str__(self):
        return f"{self.delivery_method} delivery for {self.notification}"


class NotificationPreference(BaseModel):
    """User preferences for notification types"""

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='notification_preferences'
    )

    # Channel preferences
    email_enabled = models.BooleanField(default=True)
    sms_enabled = models.BooleanField(default=False)
    push_enabled = models.BooleanField(default=True)
    in_app_enabled = models.BooleanField(default=True)

    # Category preferences
    exam_notifications = models.BooleanField(default=True)
    moderation_notifications = models.BooleanField(default=True)
    system_notifications = models.BooleanField(default=True)
    deadline_notifications = models.BooleanField(default=True)

    # Quiet hours
    quiet_hours_start = models.TimeField(null=True, blank=True)
    quiet_hours_end = models.TimeField(null=True, blank=True)

    # Contact information
    email_address = models.EmailField(blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    device_tokens = models.JSONField(default=list)  # For push notifications

    class Meta:
        app_label = 'notifications'
        verbose_name = _('Notification Preference')
        verbose_name_plural = _('Notification Preferences')

    def __str__(self):
        return f"Preferences for {self.user}"


class NotificationEvent(BaseModel):
    """System events that trigger notifications"""

    EVENT_EXAM_CREATED = 'exam_created'
    EVENT_EXAM_SUBMITTED = 'exam_submitted'
    EVENT_EXAM_REVIEWED = 'exam_reviewed'
    EVENT_EXAM_APPROVED = 'exam_approved'
    EVENT_MODERATION_ASSIGNED = 'moderation_assigned'
    EVENT_MODERATION_COMPLETED = 'moderation_completed'
    EVENT_DEADLINE_APPROACHING = 'deadline_approaching'
    EVENT_DEADLINE_OVERDUE = 'deadline_overdue'

    EVENT_CHOICES = [
        (EVENT_EXAM_CREATED, _('Exam Created')),
        (EVENT_EXAM_SUBMITTED, _('Exam Submitted')),
        (EVENT_EXAM_REVIEWED, _('Exam Reviewed')),
        (EVENT_EXAM_APPROVED, _('Exam Approved')),
        (EVENT_MODERATION_ASSIGNED, _('Moderation Assigned')),
        (EVENT_MODERATION_COMPLETED, _('Moderation Completed')),
        (EVENT_DEADLINE_APPROACHING, _('Deadline Approaching')),
        (EVENT_DEADLINE_OVERDUE, _('Deadline Overdue')),
    ]

    event_type = models.CharField(max_length=50, choices=EVENT_CHOICES, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)

    # Default templates for this event
    default_email_template = models.ForeignKey(
        NotificationTemplate,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='email_events'
    )
    default_sms_template = models.ForeignKey(
        NotificationTemplate,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sms_events'
    )
    default_push_template = models.ForeignKey(
        NotificationTemplate,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='push_events'
    )
    default_in_app_template = models.ForeignKey(
        NotificationTemplate,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='in_app_events'
    )

    is_active = models.BooleanField(default=True)

    class Meta:
        app_label = 'notifications'
        verbose_name = _('Notification Event')
        verbose_name_plural = _('Notification Events')

    def __str__(self):
        return self.name
