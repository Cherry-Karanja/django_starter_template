from drf_spectacular.utils import (
    extend_schema,
    OpenApiParameter,
    OpenApiExample,
    OpenApiResponse,
    OpenApiTypes,
)
from drf_spectacular.types import OpenApiTypes

# Common response definitions for security
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

# Security-specific responses
security_responses = {
    **common_responses,
    201: {
        "description": "Security event logged successfully",
        "content": {
            "application/json": {
                "examples": {
                    "security_event_logged": {
                        "summary": "Security Event Logged",
                        "value": {
                            'id': 1,
                            'event_type': 'failed_login',
                            'title': 'Failed login attempt',
                            'description': 'Multiple failed login attempts detected',
                            'severity': 'medium',
                            'status': 'active',
                            'created_at': '2023-01-01T00:00:00Z'
                        }
                    }
                }
            }
        }
    },
    202: {
        "description": "Action completed successfully",
        "content": {
            "application/json": {
                "examples": {
                    "action_completed": {
                        "summary": "Action Completed",
                        "value": {
                            'status': 'unblocked',
                            'message': 'Rate limit unblocked successfully'
                        }
                    }
                }
            }
        }
    }
}

# Audit log parameters
audit_log_parameters = [
    OpenApiParameter(
        name='event_type',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by event type',
        required=False
    ),
    OpenApiParameter(
        name='severity',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by severity (low, medium, high, critical)',
        required=False,
        enum=['low', 'medium', 'high', 'critical']
    ),
    OpenApiParameter(
        name='user',
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description='Filter by user ID',
        required=False
    ),
    OpenApiParameter(
        name='ip_address',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by IP address',
        required=False
    ),
    OpenApiParameter(
        name='start_date',
        type=OpenApiTypes.DATE,
        location=OpenApiParameter.QUERY,
        description='Start date for filtering (YYYY-MM-DD)',
        required=False
    ),
    OpenApiParameter(
        name='end_date',
        type=OpenApiTypes.DATE,
        location=OpenApiParameter.QUERY,
        description='End date for filtering (YYYY-MM-DD)',
        required=False
    ),
]

# Rate limit parameters
rate_limit_parameters = [
    OpenApiParameter(
        name='limit_type',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by limit type (ip, user, endpoint)',
        required=False,
        enum=['ip', 'user', 'endpoint']
    ),
    OpenApiParameter(
        name='is_blocked',
        type=bool,
        location=OpenApiParameter.QUERY,
        description='Filter by blocked status',
        required=False
    ),
    OpenApiParameter(
        name='endpoint',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by endpoint',
        required=False
    ),
]

# Security event parameters
security_event_parameters = [
    OpenApiParameter(
        name='event_type',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by event type',
        required=False
    ),
    OpenApiParameter(
        name='status',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by status (active, resolved, false_positive)',
        required=False,
        enum=['active', 'resolved', 'false_positive']
    ),
    OpenApiParameter(
        name='severity',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by severity (low, medium, high, critical)',
        required=False,
        enum=['low', 'medium', 'high', 'critical']
    ),
    OpenApiParameter(
        name='user',
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description='Filter by user ID',
        required=False
    ),
]

# Security settings parameters
security_settings_parameters = [
    OpenApiParameter(
        name='setting_type',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by setting type',
        required=False
    ),
    OpenApiParameter(
        name='is_enabled',
        type=bool,
        location=OpenApiParameter.QUERY,
        description='Filter by enabled status',
        required=False
    ),
]

# API key parameters
api_key_parameters = [
    OpenApiParameter(
        name='key_type',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Filter by key type',
        required=False
    ),
    OpenApiParameter(
        name='is_active',
        type=bool,
        location=OpenApiParameter.QUERY,
        description='Filter by active status',
        required=False
    ),
]

# Security dashboard response
dashboard_response = OpenApiResponse(
    description="Security dashboard data",
    response={
        'type': 'object',
        'properties': {
            'total_audit_logs': {'type': 'integer'},
            'audit_logs_today': {'type': 'integer'},
            'total_security_events': {'type': 'integer'},
            'active_security_events': {'type': 'integer'},
            'critical_events': {'type': 'integer'},
            'active_rate_limits': {'type': 'integer'},
            'total_users': {'type': 'integer'},
            'active_users': {'type': 'integer'},
            'security_health_score': {'type': 'integer'},
            'recent_security_events': {'type': 'array'},
            'recent_audit_logs': {'type': 'array'},
            'failed_login_trend': {
                'type': 'object',
                'properties': {
                    'previous_7d': {'type': 'integer'},
                    'current_7d': {'type': 'integer'},
                    'change_percent': {'type': 'number'}
                }
            }
        }
    },
    examples=[
        OpenApiExample(
            name="default",
            summary="Security Dashboard Data",
            value={
                'total_audit_logs': 1000,
                'audit_logs_today': 50,
                'total_security_events': 25,
                'active_security_events': 5,
                'critical_events': 1,
                'active_rate_limits': 3,
                'total_users': 500,
                'active_users': 450,
                'security_health_score': 85,
                'recent_security_events': [],
                'recent_audit_logs': [],
                'failed_login_trend': {
                    'previous_7d': 20,
                    'current_7d': 15,
                    'change_percent': -25.0
                }
            }
        )
    ]
)

# Log security event request schema
log_security_event_request = {
    'type': 'object',
    'properties': {
        'event_type': {
            'type': 'string',
            'description': 'Type of security event'
        },
        'title': {
            'type': 'string',
            'description': 'Event title'
        },
        'description': {
            'type': 'string',
            'description': 'Detailed event description'
        },
        'severity': {
            'type': 'string',
            'enum': ['low', 'medium', 'high', 'critical'],
            'description': 'Event severity level'
        },
        'detection_data': {
            'type': 'object',
            'description': 'Additional detection data'
        }
    },
    'required': ['event_type', 'title', 'description']
}

# Resolve security event request schema
resolve_event_request = {
    'type': 'object',
    'properties': {
        'notes': {
            'type': 'string',
            'description': 'Resolution notes'
        }
    },
    'required': []
}