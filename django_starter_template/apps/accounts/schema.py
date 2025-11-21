from drf_spectacular.utils import (
    extend_schema,
    OpenApiParameter,
    OpenApiExample,
    OpenApiResponse,
    OpenApiTypes,
)
from drf_spectacular.types import OpenApiTypes

# Common response definitions
common_responses = {
    400: {
        "description": "Bad request - invalid input",
        "content": {
            "application/json": {
                "examples": {
                    "validation_error": {
                        "summary": "Validation Error",
                        "value": {
                            "type": "validation_error",
                            "errors": {
                                "field": ["Error message"]
                            }
                        }
                    }
                }
            }
        }
    },
    401: {
        "description": "Authentication required",
        "content": {
            "application/json": {
                "examples": {
                    "auth_required": {
                        "summary": "Authentication Required",
                        "value": {
                            "detail": "Authentication credentials were not provided."
                        }
                    }
                }
            }
        }
    },
    403: {
        "description": "Permission denied",
        "content": {
            "application/json": {
                "examples": {
                    "permission_denied": {
                        "summary": "Permission Denied",
                        "value": {
                            "detail": "You do not have permission to perform this action."
                        }
                    }
                }
            }
        }
    },
    404: {
        "description": "Resource not found",
        "content": {
            "application/json": {
                "examples": {
                    "not_found": {
                        "summary": "Not Found",
                        "value": {
                            "detail": "Not found."
                        }
                    }
                }
            }
        }
    },
    500: {
        "description": "Server error",
        "content": {
            "application/json": {
                "examples": {
                    "server_error": {
                        "summary": "Server Error",
                        "value": {
                            "detail": "A server error occurred."
                        }
                    }
                }
            }
        }
    }
}

# User management parameters
user_parameters = [
    OpenApiParameter(
        name="search",
        type=OpenApiTypes.STR,
        description="Search across email, name, employee_id",
        required=False
    ),
    OpenApiParameter(
        name="role_name",
        type=OpenApiTypes.STR,
        description="Filter by role name",
        required=False
    ),
    OpenApiParameter(
        name="is_active",
        type=OpenApiTypes.BOOL,
        description="Filter by active status",
        required=False
    ),
    OpenApiParameter(
        name="ordering",
        type=OpenApiTypes.STR,
        description="Order by field (prefix with - for descending)",
        required=False
    ),
]

# Role management parameters
role_parameters = [
    OpenApiParameter(
        name="search",
        type=OpenApiTypes.STR,
        description="Search across role name and description",
        required=False
    ),
    OpenApiParameter(
        name="is_active",
        type=OpenApiTypes.BOOL,
        description="Filter by active status",
        required=False
    ),
    OpenApiParameter(
        name="ordering",
        type=OpenApiTypes.STR,
        description="Order by field (prefix with - for descending)",
        required=False
    ),
]

# Permission management parameters
permission_parameters = [
    OpenApiParameter(
        name="search",
        type=OpenApiTypes.STR,
        description="Search across permission name, codename, and description",
        required=False
    ),
    OpenApiParameter(
        name="content_type",
        type=OpenApiTypes.STR,
        description="Filter by content type (app.model)",
        required=False
    ),
    OpenApiParameter(
        name="ordering",
        type=OpenApiTypes.STR,
        description="Order by field (prefix with - for descending)",
        required=False
    ),
]

# Session management parameters
session_parameters = [
    OpenApiParameter(
        name="search",
        type=OpenApiTypes.STR,
        description="Search across IP address and user agent",
        required=False
    ),
    OpenApiParameter(
        name="is_active",
        type=OpenApiTypes.BOOL,
        description="Filter by active status",
        required=False
    ),
    OpenApiParameter(
        name="risk_score_min",
        type=OpenApiTypes.INT,
        description="Filter by minimum risk score",
        required=False
    ),
    OpenApiParameter(
        name="risk_score_max",
        type=OpenApiTypes.INT,
        description="Filter by maximum risk score",
        required=False
    ),
    OpenApiParameter(
        name="ordering",
        type=OpenApiTypes.STR,
        description="Order by field (prefix with - for descending)",
        required=False
    ),
]

# Login attempt parameters
login_attempt_parameters = [
    OpenApiParameter(
        name="search",
        type=OpenApiTypes.STR,
        description="Search across email and IP address",
        required=False
    ),
    OpenApiParameter(
        name="success",
        type=OpenApiTypes.BOOL,
        description="Filter by login success status",
        required=False
    ),
    OpenApiParameter(
        name="failure_reason",
        type=OpenApiTypes.STR,
        description="Filter by failure reason",
        required=False
    ),
    OpenApiParameter(
        name="ip_address",
        type=OpenApiTypes.STR,
        description="Filter by IP address",
        required=False
    ),
    OpenApiParameter(
        name="ordering",
        type=OpenApiTypes.STR,
        description="Order by field (prefix with - for descending)",
        required=False
    ),
]

# User approval request schema
user_approval_request = {
    'type': 'object',
    'properties': {
        'notes': {
            'type': 'string',
            'description': 'Optional notes for the approval',
            'maxLength': 500
        }
    },
    'required': []
}

# Role change request schema
role_change_request = {
    'type': 'object',
    'properties': {
        'role_name': {
            'type': 'string',
            'description': 'Name of the role to assign',
            'maxLength': 100
        },
        'notes': {
            'type': 'string',
            'description': 'Optional notes for the role change',
            'maxLength': 500
        }
    },
    'required': ['role_name']
}

# Permission update request schema
permission_update_request = {
    'type': 'object',
    'properties': {
        'permissions': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'permission_id': {'type': 'integer'},
                    'granted': {'type': 'boolean'}
                },
                'required': ['permission_id', 'granted']
            },
            'description': 'List of permissions to grant or revoke'
        },
        'notes': {
            'type': 'string',
            'description': 'Optional notes for the permission change',
            'maxLength': 500
        }
    },
    'required': ['permissions']
}

# User statistics response
user_stats_response = {
    200: {
        'description': "User statistics",
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'total_users': {'type': 'integer'},
                        'active_users': {'type': 'integer'},
                        'inactive_users': {'type': 'integer'},
                        'users_by_role': {
                            'type': 'object',
                            'additionalProperties': {'type': 'integer'}
                        },
                        'recent_registrations': {'type': 'integer'},
                        'pending_approvals': {'type': 'integer'}
                    }
                }
            }
        }
    },
    **common_responses
}

# Session statistics response
session_stats_response = {
    200: {
        'description': "Session statistics",
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'total_sessions': {'type': 'integer'},
                        'active_sessions': {'type': 'integer'},
                        'expired_sessions': {'type': 'integer'},
                        'high_risk_sessions': {'type': 'integer'},
                        'sessions_by_device_type': {
                            'type': 'object',
                            'additionalProperties': {'type': 'integer'}
                        }
                    }
                }
            }
        }
    },
    **common_responses
}