from rest_framework import viewsets, status, mixins
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext_lazy as _
from django.db import transaction, models
from django.utils import timezone
from django.contrib.auth import get_user_model
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiTypes
from .models import (
    NotificationTemplate,
    Notification,
    NotificationDelivery,
    NotificationPreference,
    NotificationEvent
)
from .serializers import (
    NotificationTemplateSerializer,
    NotificationSerializer,
    NotificationDeliverySerializer,
    NotificationPreferenceSerializer,
    NotificationEventSerializer,
    SendNotificationSerializer,
    BulkNotificationSerializer,
    MarkNotificationsReadSerializer
)
from .permissions import (
    CanManageNotifications,
    CanManageTemplates,
    CanViewAnalytics,
    NotificationPreferencesPermission
)
from .schema import (
    common_responses,
    notification_responses,
    template_parameters,
    notification_parameters,
    delivery_parameters,
    statistics_responses
)

User = get_user_model()


@extend_schema_view(
    list=extend_schema(
        tags=["Notifications"],
        summary="List notification templates",
        description="Retrieve a list of notification templates with optional filtering by type.",
        parameters=template_parameters,
        responses={
            200: NotificationTemplateSerializer(many=True),
            **common_responses
        }
    ),
    create=extend_schema(
        tags=["Notifications"],
        summary="Create notification template",
        description="Create a new notification template for sending notifications.",
        responses={
            201: NotificationTemplateSerializer,
            **common_responses
        }
    ),
    retrieve=extend_schema(
        tags=["Notifications"],
        summary="Retrieve notification template",
        description="Retrieve detailed information about a specific notification template.",
        responses={
            200: NotificationTemplateSerializer,
            **common_responses
        }
    ),
    update=extend_schema(
        tags=["Notifications"],
        summary="Update notification template",
        description="Update an existing notification template.",
        responses={
            200: NotificationTemplateSerializer,
            **common_responses
        }
    ),
    partial_update=extend_schema(
        tags=["Notifications"],
        summary="Partial update notification template",
        description="Partially update a notification template.",
        responses={
            200: NotificationTemplateSerializer,
            **common_responses
        }
    ),
    destroy=extend_schema(
        tags=["Notifications"],
        summary="Delete notification template",
        description="Delete a notification template.",
        responses={
            204: None,
            **common_responses
        }
    )
)
@extend_schema(tags=["Notifications"])
class NotificationTemplateViewSet(viewsets.ModelViewSet):
    """ViewSet for managing notification templates"""

    queryset = NotificationTemplate.objects.all()
    serializer_class = NotificationTemplateSerializer
    permission_classes = [CanManageTemplates]

    def get_queryset(self):
        queryset = super().get_queryset()
        template_type = self.request.query_params.get('type')
        if template_type:
            queryset = queryset.filter(template_type=template_type)
        return queryset.filter(is_active=True)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='type',
                type=str,
                description='Filter by template type (email, sms, push, in_app)',
                required=False
            )
        ]
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)


@extend_schema_view(
    list=extend_schema(
        tags=["Notifications"],
        summary="List notifications",
        description="Retrieve a list of notifications with optional filtering by status, priority, and template type.",
        parameters=notification_parameters,
        responses={
            200: NotificationSerializer(many=True),
            **common_responses
        }
    ),
    create=extend_schema(
        tags=["Notifications"],
        summary="Create notification",
        description="Create a new notification manually.",
        responses={
            201: NotificationSerializer,
            **common_responses
        }
    ),
    retrieve=extend_schema(
        tags=["Notifications"],
        summary="Retrieve notification",
        description="Retrieve detailed information about a specific notification.",
        responses={
            200: NotificationSerializer,
            **common_responses
        }
    ),
    update=extend_schema(
        tags=["Notifications"],
        summary="Update notification",
        description="Update an existing notification.",
        responses={
            200: NotificationSerializer,
            **common_responses
        }
    ),
    partial_update=extend_schema(
        tags=["Notifications"],
        summary="Partial update notification",
        description="Partially update a notification.",
        responses={
            200: NotificationSerializer,
            **common_responses
        }
    ),
    destroy=extend_schema(
        tags=["Notifications"],
        summary="Delete notification",
        description="Delete a notification.",
        responses={
            204: None,
            **common_responses
        }
    )
)
@extend_schema(tags=["Notifications"])
class NotificationViewSet(viewsets.ModelViewSet):
    """ViewSet for managing notifications"""

    serializer_class = NotificationSerializer
    permission_classes = [CanManageNotifications]
    queryset = Notification.objects.none()  # Provide empty queryset for schema generation

    def get_queryset(self):
        queryset = Notification.objects.select_related('recipient', 'template')

        # Filter by current user if not staff
        if not self.request.user.is_staff and not self.request.user.is_superuser:
            queryset = queryset.filter(recipient=self.request.user)

        # Apply filters
        status_filter = self.request.query_params.get('status')
        priority_filter = self.request.query_params.get('priority')
        template_type = self.request.query_params.get('template_type')

        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if priority_filter:
            queryset = queryset.filter(priority=priority_filter)
        if template_type:
            queryset = queryset.filter(template__template_type=template_type)

        return queryset.order_by('-created_at')

    @extend_schema(
        summary="Mark notification as read",
        description="Mark a specific notification as read and update its delivery status.",
        responses={
            200: NotificationSerializer,
            **common_responses
        }
    )
    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        """Mark a notification as read"""
        notification = self.get_object()
        notification.status = Notification.STATUS_DELIVERED
        notification.delivered_at = timezone.now()
        notification.save()
        serializer = self.get_serializer(notification)
        return Response(serializer.data)

    @extend_schema(
        summary="Retry failed notification",
        description="Retry sending a notification that previously failed.",
        responses={
            200: NotificationSerializer,
            400: OpenApiTypes.OBJECT,
            **common_responses
        }
    )
    @action(detail=True, methods=['post'])
    def retry(self, request, pk=None):
        """Retry sending a failed notification"""
        notification = self.get_object()
        if notification.status != Notification.STATUS_FAILED:
            return Response(
                {'error': _('Only failed notifications can be retried')},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Reset status and increment retry count
        notification.status = Notification.STATUS_PENDING
        notification.retry_count += 1
        notification.last_error = ''
        notification.save()

        try:
            from .tasks import send_notification
            send_notification.delay(str(notification.id))
        except Exception as e:
            logger.error(f"Failed to schedule notification {notification.id}: {str(e)}")
        serializer = self.get_serializer(notification)
        return Response(serializer.data)

    @extend_schema(
        summary="Bulk notification actions",
        description="Perform bulk operations on multiple notifications (cancel, retry, mark as delivered).",
        request=BulkNotificationSerializer,
        responses={
            200: OpenApiTypes.OBJECT,
            **common_responses
        }
    )
    @action(detail=False, methods=['post'])
    def bulk_action(self, request):
        """Perform bulk actions on notifications"""
        serializer = BulkNotificationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        notification_ids = serializer.validated_data['notification_ids']
        action = serializer.validated_data['action']

        notifications = Notification.objects.filter(id__in=notification_ids)

        if action == 'cancel':
            notifications.filter(status=Notification.STATUS_PENDING).update(
                status=Notification.STATUS_CANCELLED
            )
        elif action == 'retry':
            notifications.filter(status=Notification.STATUS_FAILED).update(
                status=Notification.STATUS_PENDING,
                retry_count=models.F('retry_count') + 1,
                last_error=''
            )
        elif action == 'mark_delivered':
            notifications.filter(status__in=[Notification.STATUS_SENT, Notification.STATUS_PENDING]).update(
                status=Notification.STATUS_DELIVERED,
                delivered_at=timezone.now()
            )

        return Response({'message': _(f'Bulk {action} completed')})

    @extend_schema(
        summary="Notification statistics",
        description="Get comprehensive notification statistics including totals and status breakdowns.",
        responses=statistics_responses
    )
    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def stats(self, request):
        """Get notification statistics for the current user"""

        total = Notification.objects.count()
        sent = Notification.objects.filter(status=Notification.STATUS_SENT).count()
        pending = Notification.objects.filter(status=Notification.STATUS_PENDING).count()
        unread = Notification.objects.filter(status__in=[Notification.STATUS_SENT, Notification.STATUS_PENDING]).count()
        delivered = Notification.objects.filter(status=Notification.STATUS_DELIVERED).count()
        failed = Notification.objects.filter(status=Notification.STATUS_FAILED).count()

        return Response({
            'total': total,
            'sent': sent,
            'delivered': delivered,
            'failed': failed,
            'pending': pending,
            'unread': unread
        })


@extend_schema_view(
    list=extend_schema(
        tags=["Notifications"],
        summary="List notification deliveries",
        description="Retrieve a list of notification delivery records with optional filtering.",
        parameters=delivery_parameters,
        responses={
            200: NotificationDeliverySerializer(many=True),
            **common_responses
        }
    ),
    retrieve=extend_schema(
        tags=["Notifications"],
        summary="Retrieve notification delivery",
        description="Retrieve detailed information about a specific notification delivery record.",
        responses={
            200: NotificationDeliverySerializer,
            **common_responses
        }
    )
)
@extend_schema(tags=["Notifications"])
class NotificationDeliveryViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing notification delivery records"""

    queryset = NotificationDelivery.objects.select_related('notification__recipient')
    serializer_class = NotificationDeliverySerializer
    permission_classes = [CanViewAnalytics]

    def get_queryset(self):
        queryset = super().get_queryset()

        # Filter by notification if provided
        notification_id = self.request.query_params.get('notification_id')
        if notification_id:
            queryset = queryset.filter(notification_id=notification_id)

        # Filter by delivery method
        method = self.request.query_params.get('method')
        if method:
            queryset = queryset.filter(delivery_method=method)

        return queryset.order_by('-created_at')


@extend_schema_view(
    retrieve=extend_schema(
        tags=["Notifications"],
        summary="Retrieve notification preferences",
        description="Retrieve the current user's notification preferences.",
        responses={
            200: NotificationPreferenceSerializer,
            **common_responses
        }
    ),
    update=extend_schema(
        tags=["Notifications"],
        summary="Update notification preferences",
        description="Update the current user's notification preferences.",
        responses={
            200: NotificationPreferenceSerializer,
            **common_responses
        }
    ),
    partial_update=extend_schema(
        tags=["Notifications"],
        summary="Partial update notification preferences",
        description="Partially update the current user's notification preferences.",
        responses={
            200: NotificationPreferenceSerializer,
            **common_responses
        }
    )
)
@extend_schema(tags=["Notifications"])
class NotificationPreferenceViewSet(mixins.RetrieveModelMixin,
                                   mixins.UpdateModelMixin,
                                   viewsets.GenericViewSet):
    """ViewSet for managing notification preferences"""

    serializer_class = NotificationPreferenceSerializer
    permission_classes = [NotificationPreferencesPermission]
    queryset = NotificationPreference.objects.none()  # Provide empty queryset for schema generation

    def get_queryset(self):
        return NotificationPreference.objects.filter(user=self.request.user)

    def get_object(self):
        """Get or create preferences for the current user"""
        obj, created = NotificationPreference.objects.get_or_create(
            user=self.request.user,
            defaults={
                'email_enabled': True,
                'sms_enabled': False,
                'push_enabled': True,
                'in_app_enabled': True,
                'exam_notifications': True,
                'moderation_notifications': True,
                'system_notifications': True,
                'deadline_notifications': True,
            }
        )
        return obj


@extend_schema_view(
    list=extend_schema(
        tags=["Notifications"],
        summary="List notification events",
        description="Retrieve a list of notification events and system activity logs.",
        responses={
            200: NotificationEventSerializer(many=True),
            **common_responses
        }
    ),
    retrieve=extend_schema(
        tags=["Notifications"],
        summary="Retrieve notification event",
        description="Retrieve detailed information about a specific notification event.",
        responses={
            200: NotificationEventSerializer,
            **common_responses
        }
    )
)
@extend_schema(tags=["Notifications"])
class NotificationEventViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing notification events"""

    queryset = NotificationEvent.objects.filter(is_active=True)
    serializer_class = NotificationEventSerializer
    permission_classes = [CanManageTemplates]


@extend_schema(
    tags=["Notifications"],
    summary="Send notification",
    description="Send notifications to multiple recipients using a notification template.",
    request=SendNotificationSerializer,
    responses={
        201: OpenApiTypes.OBJECT,
        **common_responses
    }
)
@api_view(['POST'])
@permission_classes([CanManageNotifications])
def send_notification(request):
    """Send a notification using a template"""
    serializer = SendNotificationSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    template = get_object_or_404(NotificationTemplate, id=data['template_id'])

    notifications_created = []

    with transaction.atomic():
        for recipient_id in data['recipient_ids']:
            recipient = get_object_or_404(User, id=recipient_id)

            # Create notification
            notification = Notification.objects.create(
                recipient=recipient,
                template=template,
                subject=data.get('subject', template.subject),
                body=template.body,  # Would be processed with template variables
                data=data['data'],
                scheduled_at=data.get('scheduled_at'),
                priority=data.get('priority', 'medium')
            )
            notifications_created.append(notification.id)

    return Response({
        'message': _(f'Created {len(notifications_created)} notifications'),
        'notification_ids': notifications_created
    }, status=status.HTTP_201_CREATED)


@extend_schema(
    tags=["Notifications"],
    summary="Get user notifications",
    description="Get current user's notifications with optional filtering and pagination.",
    parameters=[
        OpenApiParameter(name='status', type=str, location=OpenApiParameter.QUERY, description='Filter by notification status'),
        OpenApiParameter(name='unread_only', type=bool, location=OpenApiParameter.QUERY, description='Show only unread notifications'),
        OpenApiParameter(name='page', type=int, location=OpenApiParameter.QUERY, description='Page number'),
        OpenApiParameter(name='page_size', type=int, location=OpenApiParameter.QUERY, description='Items per page (max 100)')
    ],
    responses={
        200: OpenApiTypes.OBJECT,
        **common_responses
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_notifications(request):
    """Get current user's notifications"""
    notifications = Notification.objects.filter(
        recipient=request.user
    ).select_related('template').order_by('-created_at')

    # Apply filters
    status_filter = request.query_params.get('status')
    unread_only = request.query_params.get('unread_only', 'false').lower() == 'true'

    if status_filter:
        notifications = notifications.filter(status=status_filter)
    if unread_only:
        notifications = notifications.exclude(status=Notification.STATUS_DELIVERED)

    # Pagination
    page = request.query_params.get('page', 1)
    page_size = min(int(request.query_params.get('page_size', 20)), 100)

    start = (int(page) - 1) * page_size
    end = start + page_size

    serializer = NotificationSerializer(notifications[start:end], many=True)
    return Response({
        'count': notifications.count(),
        'results': serializer.data
    })


@extend_schema(
    tags=["Notifications"],
    summary="Get notification statistics",
    description="Returns comprehensive statistics about notifications including totals and recent activity.",
    responses=statistics_responses
)
@api_view(['GET'])
@permission_classes([CanViewAnalytics])
def notification_stats(request):
    """Get notification statistics"""
    # Basic stats
    total_notifications = Notification.objects.count()
    sent_notifications = Notification.objects.filter(status=Notification.STATUS_SENT).count()
    delivered_notifications = Notification.objects.filter(status=Notification.STATUS_DELIVERED).count()
    failed_notifications = Notification.objects.filter(status=Notification.STATUS_FAILED).count()

    # Recent activity (last 30 days)
    from django.utils import timezone
    thirty_days_ago = timezone.now() - timezone.timedelta(days=30)

    recent_notifications = Notification.objects.filter(created_at__gte=thirty_days_ago)
    recent_sent = recent_notifications.filter(status=Notification.STATUS_SENT).count()
    recent_delivered = recent_notifications.filter(status=Notification.STATUS_DELIVERED).count()
    recent_failed = recent_notifications.filter(status=Notification.STATUS_FAILED).count()

    return Response({
        'total': total_notifications,
        'sent': sent_notifications,
        'delivered': delivered_notifications,
        'failed': failed_notifications,
        'recent': {
            'total': recent_notifications.count(),
            'sent': recent_sent,
            'delivered': recent_delivered,
            'failed': recent_failed,
        }
    })


@extend_schema(
    tags=["Notifications"],
    summary="Mark notifications as read",
    description="Mark multiple notifications as read for the current user.",
    request=MarkNotificationsReadSerializer,
    responses={
        200: OpenApiTypes.OBJECT,
        **common_responses
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_notifications_read(request):
    """Mark multiple notifications as read"""
    serializer = MarkNotificationsReadSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    notification_ids = serializer.validated_data['notification_ids']

    # Only allow users to mark their own notifications as read
    updated_count = Notification.objects.filter(
        id__in=notification_ids,
        recipient=request.user,
        status__in=[Notification.STATUS_SENT, Notification.STATUS_PENDING]
    ).update(
        status=Notification.STATUS_DELIVERED,
        delivered_at=timezone.now()
    )

    return Response({
        'message': _(f'Marked {updated_count} notifications as read')
    })
