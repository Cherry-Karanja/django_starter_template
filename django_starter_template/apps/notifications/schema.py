from drf_spectacular.utils import (
    extend_schema,
    OpenApiParameter,
    OpenApiExample,
    OpenApiResponse,
    OpenApiTypes,
)
from drf_spectacular.types import OpenApiTypes

# Common response definitions for notifications
common_responses = {
    400: OpenApiResponse(
        description="Bad request - invalid input",
        response={
            "type": "object",
            "properties": {
                "type": {"type": "string", "example": "validation_error"},
                "errors": {
                    "type": "object",
                    "additionalProperties": {"type": "array", "items": {"type": "string"}}
                }
            }
        },
        examples=[
            OpenApiExample(
                name="validation_error",
                summary="Validation Error",
                value={
                    "type": "validation_error",
                    "errors": {
                        "field": ["Error message"]
                    }
                }
            )
        ]
    ),
    401: OpenApiResponse(
        description="Authentication required",
        response={
            "type": "object",
            "properties": {
                "detail": {"type": "string"}
            }
        },
        examples=[
            OpenApiExample(
                name="auth_required",
                summary="Authentication Required",
                value={
                    "detail": "Authentication credentials were not provided."
                }
            )
        ]
    ),
    403: OpenApiResponse(
        description="Permission denied",
        response={
            "type": "object",
            "properties": {
                "detail": {"type": "string"}
            }
        },
        examples=[
            OpenApiExample(
                name="permission_denied",
                summary="Permission Denied",
                value={
                    "detail": "You do not have permission to perform this action."
                }
            )
        ]
    ),
    404: OpenApiResponse(
        description="Resource not found",
        response={
            "type": "object",
            "properties": {
                "detail": {"type": "string"}
            }
        },
        examples=[
            OpenApiExample(
                name="not_found",
                summary="Not Found",
                value={
                    "detail": "Not found."
                }
            )
        ]
    ),
    500: OpenApiResponse(
        description="Server error",
        response={
            "type": "object",
            "properties": {
                "detail": {"type": "string"}
            }
        },
        examples=[
            OpenApiExample(
                name="server_error",
                summary="Server Error",
                value={
                    "detail": "A server error occurred."
                }
            )
        ]
    )
}

# Notification-specific responses
notification_responses = {
    **common_responses,
    201: {
        "description": "Notification created successfully",
        "content": {
            "application/json": {
                "examples": {
                    "notification_created": {
                        "summary": "Notification Created",
                        "value": {
                            'id': 1,
                            'recipient': 1,
                            'template': 1,
                            'subject': 'Welcome!',
                            'body': 'Welcome to our platform...',
                            'status': 'pending',
                            'priority': 'medium',
                            'created_at': '2023-01-01T00:00:00Z'
                        }
                    }
                }
            }
        }
    },
    202: {
        "description": "Bulk operation accepted",
        "content": {
            "application/json": {
                "examples": {
                    "bulk_operation": {
                        "summary": "Bulk Operation Accepted",
                        "value": {
                            'message': 'Bulk action completed'
                        }
                    }
                }
            }
        }
    }
}

# Common parameters for notifications
notification_parameters = [
    OpenApiParameter(
        name='status',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by notification status (pending, sent, delivered, failed, cancelled)',
        required=False,
        enum=['pending', 'sent', 'delivered', 'failed', 'cancelled']
    ),
    OpenApiParameter(
        name='priority',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by priority (low, medium, high, urgent)',
        required=False,
        enum=['low', 'medium', 'high', 'urgent']
    ),
    OpenApiParameter(
        name='template_type',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by template type (email, sms, push, in_app)',
        required=False,
        enum=['email', 'sms', 'push', 'in_app']
    ),
    OpenApiParameter(
        name='unread_only',
        type=bool,
        location=OpenApiParameter.QUERY,
        description='Show only unread notifications',
        required=False
    ),
]

# Template parameters
template_parameters = [
    OpenApiParameter(
        name='type',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by template type (email, sms, push, in_app)',
        required=False,
        enum=['email', 'sms', 'push', 'in_app']
    ),
]

# Delivery parameters
delivery_parameters = [
    OpenApiParameter(
        name='notification_id',
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description='Filter by notification ID',
        required=False
    ),
    OpenApiParameter(
        name='method',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by delivery method (email, sms, push, webhook)',
        required=False,
        enum=['email', 'sms', 'push', 'webhook']
    ),
]

# Statistics responses
statistics_responses = {
    200: OpenApiResponse(
        description="Notification statistics",
        response={
            'type': 'object',
            'properties': {
                'total': {'type': 'integer'},
                'sent': {'type': 'integer'},
                'delivered': {'type': 'integer'},
                'failed': {'type': 'integer'},
                'pending': {'type': 'integer'},
                'unread': {'type': 'integer'}
            }
        },
        examples=[
            OpenApiExample(
                name="statistics",
                summary="Notification Statistics",
                value={
                    'total': 1000,
                    'sent': 850,
                    'delivered': 800,
                    'failed': 50,
                    'pending': 100,
                    'unread': 200
                }
            )
        ]
    )
}

# Bulk operation request schema
bulk_operation_request = {
    'type': 'object',
    'properties': {
        'notification_ids': {
            'type': 'array',
            'items': {'type': 'integer'},
            'description': 'List of notification IDs to operate on'
        },
        'action': {
            'type': 'string',
            'enum': ['cancel', 'retry', 'mark_delivered'],
            'description': 'Action to perform on the notifications'
        }
    },
    'required': ['notification_ids', 'action']
}

# Send notification request schema
send_notification_request = {
    'type': 'object',
    'properties': {
        'template_id': {
            'type': 'integer',
            'description': 'ID of the notification template to use'
        },
        'recipient_ids': {
            'type': 'array',
            'items': {'type': 'integer'},
            'description': 'List of user IDs to send notifications to'
        },
        'subject': {
            'type': 'string',
            'description': 'Custom subject (optional, overrides template)'
        },
        'data': {
            'type': 'object',
            'description': 'Template variables data'
        },
        'scheduled_at': {
            'type': 'string',
            'format': 'date-time',
            'description': 'Schedule notification for later (ISO 8601 format)'
        },
        'priority': {
            'type': 'string',
            'enum': ['low', 'medium', 'high', 'urgent'],
            'description': 'Notification priority'
        }
    },
    'required': ['template_id', 'recipient_ids']
}

# Mark notifications read request schema
mark_read_request = {
    'type': 'object',
    'properties': {
        'notification_ids': {
            'type': 'array',
            'items': {'type': 'integer'},
            'description': 'List of notification IDs to mark as read'
        }
    },
    'required': ['notification_ids']
}