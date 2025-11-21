from drf_spectacular.utils import (
    extend_schema,
    OpenApiParameter,
    OpenApiExample,
    OpenApiResponse,
    OpenApiTypes,
)
from drf_spectacular.types import OpenApiTypes
from django.urls import re_path, path
from rest_framework import viewsets

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

pagination_parameters = [
    OpenApiParameter(
        name='page',
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description='Page number',
        required=False,
    ),
    OpenApiParameter(
        name='page_size',
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description='Number of items per page',
        required=False,
    ),
]

workflow_responses = {
    **common_responses,
    422: {
        'description': "Invalid workflow transition",
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'detail': {'type': 'string'}
                    }
                },
                'examples': {
                    'default': {
                        'detail': 'Invalid status transition.'
                    }
                }
            }
        }
    }
}

async_task_responses = {
    **common_responses,
    202: {
        'description': "Task accepted",
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'task_id': {'type': 'string'},
                        'status': {'type': 'string'}
                    }
                },
                'examples': {
                    'default': {
                        'task_id': 'uuid',
                        'status': 'PENDING'
                    }
                }
            }
        }
    }
}

file_upload_parameters = [
    OpenApiParameter(
        name='file',
        type=OpenApiTypes.BINARY,
        location='form',
        description='File to upload',
        required=True,
    )
]

filtering_parameters = [
    OpenApiParameter(
        name='search',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Search term',
        required=False,
    ),
    OpenApiParameter(
        name='ordering',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Ordering field (prefix with - for descending)',
        required=False,
    ),
]