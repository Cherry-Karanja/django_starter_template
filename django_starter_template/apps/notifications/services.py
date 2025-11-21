import logging
from typing import Dict, List, Optional
from django.template import Template, Context
from django.utils import timezone
from django.contrib.auth import get_user_model
from .models import (
    NotificationTemplate,
    Notification,
    NotificationDelivery,
    NotificationPreference,
    NotificationEvent
)

logger = logging.getLogger(__name__)
User = get_user_model()


class NotificationService:
    """Service for handling notification operations"""

    @staticmethod
    def render_template(template: NotificationTemplate, data: Dict) -> Dict[str, str]:
        """Render template with provided data"""
        try:
            context = Context(data)
            rendered = {
                'subject': Template(template.subject or '').render(context) if template.subject else '',
                'body': Template(template.body).render(context)
            }
            return rendered
        except Exception as e:
            logger.error(f"Template rendering error: {e}")
            return {
                'subject': template.subject or '',
                'body': template.body
            }

    @staticmethod
    def create_notification(
        recipient: User,
        template: NotificationTemplate,
        data: Optional[Dict] = None,
        scheduled_at: Optional[timezone.datetime] = None,
        priority: str = 'medium'
    ) -> Notification:
        """Create a notification instance"""
        data = data or {}

        # Render template
        rendered = NotificationService.render_template(template, data)

        # Create notification
        notification = Notification.objects.create(
            recipient=recipient,
            template=template,
            subject=rendered['subject'],
            body=rendered['body'],
            data=data,
            scheduled_at=scheduled_at,
            priority=priority
        )

        logger.info(f"Created notification {notification.id} for user {recipient.get_username()}")
        return notification

    @staticmethod
    def send_notification(notification: Notification) -> bool:
        """Send a notification through appropriate channels"""
        try:
            # Check user preferences
            preferences = NotificationPreference.objects.filter(user=notification.recipient).first()
            if not preferences:
                # Create default preferences
                preferences = NotificationPreference.objects.create(
                    user=notification.recipient,
                    email_enabled=True,
                    sms_enabled=False,
                    push_enabled=True,
                    in_app_enabled=True
                )

            # Determine delivery channels based on template type and user preferences
            channels = NotificationService._get_delivery_channels(
                notification.template.template_type,
                preferences
            )

            success = False
            for channel in channels:
                delivery = NotificationDelivery.objects.create(
                    notification=notification,
                    delivery_method=channel,
                    recipient_address=NotificationService._get_recipient_address(
                        notification.recipient, channel, preferences
                    )
                )

                # Attempt delivery
                if NotificationService._deliver_to_channel(delivery):
                    success = True
                    delivery.status = NotificationDelivery.STATUS_DELIVERED
                    delivery.delivered_at = timezone.now()
                else:
                    delivery.status = NotificationDelivery.STATUS_FAILED
                    delivery.error_message = "Delivery failed"

                delivery.save()

            # Update notification status
            if success:
                notification.status = Notification.STATUS_DELIVERED
                notification.delivered_at = timezone.now()
            else:
                notification.status = Notification.STATUS_FAILED
                notification.last_error = "All delivery channels failed"

            notification.sent_at = timezone.now()
            notification.save()

            return success

        except Exception as e:
            logger.error(f"Failed to send notification {notification.id}: {e}")
            notification.status = Notification.STATUS_FAILED
            notification.last_error = str(e)
            notification.save()
            return False

    @staticmethod
    def _get_delivery_channels(template_type: str, preferences: NotificationPreference) -> List[str]:
        """Determine which channels to use based on template type and preferences"""
        channels = []

        if template_type == NotificationTemplate.TYPE_EMAIL and preferences.email_enabled:
            channels.append(NotificationDelivery.DELIVERY_EMAIL)
        elif template_type == NotificationTemplate.TYPE_SMS and preferences.sms_enabled:
            channels.append(NotificationDelivery.DELIVERY_SMS)
        elif template_type == NotificationTemplate.TYPE_PUSH and preferences.push_enabled:
            channels.append(NotificationDelivery.DELIVERY_PUSH)
        elif template_type == NotificationTemplate.TYPE_IN_APP and preferences.in_app_enabled:
            channels.append(NotificationDelivery.DELIVERY_IN_APP)

        return channels

    @staticmethod
    def _get_recipient_address(user: User, channel: str, preferences: NotificationPreference) -> str:
        """Get the recipient address for a delivery channel"""
        if channel == NotificationDelivery.DELIVERY_EMAIL:
            return preferences.email_address or user.email
        elif channel == NotificationDelivery.DELIVERY_SMS:
            return preferences.phone_number or ''
        elif channel == NotificationDelivery.DELIVERY_PUSH:
            # Return device tokens as JSON string
            return str(preferences.device_tokens)
        elif channel == NotificationDelivery.DELIVERY_IN_APP:
            return str(user.id)
        return ''

    @staticmethod
    def _deliver_to_channel(delivery: NotificationDelivery) -> bool:
        """Deliver notification to a specific channel"""
        try:
            if delivery.delivery_method == NotificationDelivery.DELIVERY_EMAIL:
                return NotificationService._send_email(delivery)
            elif delivery.delivery_method == NotificationDelivery.DELIVERY_SMS:
                return NotificationService._send_sms(delivery)
            elif delivery.delivery_method == NotificationDelivery.DELIVERY_PUSH:
                return NotificationService._send_push(delivery)
            elif delivery.delivery_method == NotificationDelivery.DELIVERY_IN_APP:
                return NotificationService._send_in_app(delivery)
            return False
        except Exception as e:
            logger.error(f"Channel delivery failed: {e}")
            return False

    @staticmethod
    def _send_email(delivery: NotificationDelivery) -> bool:
        """Send email notification"""
        # Placeholder for email sending logic
        # In production, integrate with SendGrid, SES, etc.
        logger.info(f"Sending email to {delivery.recipient_address}: {delivery.notification.subject}")
        return True  # Simulate success

    @staticmethod
    def _send_sms(delivery: NotificationDelivery) -> bool:
        """Send SMS notification"""
        # Placeholder for SMS sending logic
        # In production, integrate with Twilio, AWS SNS, etc.
        logger.info(f"Sending SMS to {delivery.recipient_address}: {delivery.notification.body[:50]}...")
        return True  # Simulate success

    @staticmethod
    def _send_push(delivery: NotificationDelivery) -> bool:
        """Send push notification"""
        # Placeholder for push notification logic
        # In production, integrate with FCM, APNS, etc.
        logger.info(f"Sending push notification to devices: {delivery.recipient_address}")
        return True  # Simulate success

    @staticmethod
    def _send_in_app(delivery: NotificationDelivery) -> bool:
        """Send in-app notification"""
        # For in-app notifications, we just mark as delivered
        # The frontend will handle displaying the notification
        logger.info(f"In-app notification created for user {delivery.notification.recipient.get_username()}")
        return True

    @staticmethod
    def trigger_event_notification(
        event_type: str,
        recipient: User,
        data: Optional[Dict] = None,
        priority: str = 'medium'
    ) -> Optional[Notification]:
        """Trigger a notification based on a system event"""
        try:
            event = NotificationEvent.objects.get(event_type=event_type, is_active=True)

            # Get appropriate template based on user preferences
            preferences = NotificationPreference.objects.filter(user=recipient).first()
            template = None

            if preferences:
                # Try to find the most appropriate template
                if preferences.email_enabled and event.default_email_template:
                    template = event.default_email_template
                elif preferences.sms_enabled and event.default_sms_template:
                    template = event.default_sms_template
                elif preferences.push_enabled and event.default_push_template:
                    template = event.default_push_template
                elif preferences.in_app_enabled and event.default_in_app_template:
                    template = event.default_in_app_template

            if not template:
                logger.warning(f"No suitable template found for event {event_type}")
                return None

            return NotificationService.create_notification(
                recipient=recipient,
                template=template,
                data=data or {},
                priority=priority
            )

        except NotificationEvent.DoesNotExist:
            logger.warning(f"Event {event_type} not found or inactive")
            return None
        except Exception as e:
            logger.error(f"Failed to trigger event notification: {e}")
            return None


class NotificationAnalytics:
    """Service for notification analytics and reporting"""

    @staticmethod
    def get_delivery_stats(days: int = 30) -> Dict:
        """Get notification delivery statistics"""
        from django.utils import timezone
        since = timezone.now() - timezone.timedelta(days=days)

        notifications = Notification.objects.filter(created_at__gte=since)

        return {
            'total_sent': notifications.count(),
            'delivered': notifications.filter(status=Notification.STATUS_DELIVERED).count(),
            'failed': notifications.filter(status=Notification.STATUS_FAILED).count(),
            'pending': notifications.filter(status=Notification.STATUS_PENDING).count(),
            'delivery_rate': 0  # Calculate based on deliveries
        }

    @staticmethod
    def get_user_engagement_stats(user: User, days: int = 30) -> Dict:
        """Get user engagement statistics"""
        from django.utils import timezone
        since = timezone.now() - timezone.timedelta(days=days)

        notifications = Notification.objects.filter(
            recipient=user,
            created_at__gte=since
        )

        return {
            'total_received': notifications.count(),
            'read': notifications.filter(status=Notification.STATUS_DELIVERED).count(),
            'unread': notifications.filter(status__in=[Notification.STATUS_SENT, Notification.STATUS_PENDING]).count(),
            'engagement_rate': 0  # Calculate based on read/total
        }