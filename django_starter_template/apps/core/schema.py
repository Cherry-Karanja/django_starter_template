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
    400: OpenApiResponse(
        description="Bad request - invalid input",
        response={
            "type": "object",
            "properties": {
                "type": {"type": "string"},
                "errors": {"type": "object"}
            }
        }
    ),
    401: OpenApiResponse(
        description="Authentication required",
        response={
            "type": "object",
            "properties": {
                "detail": {"type": "string"}
            }
        }
    ),
    403: OpenApiResponse(
        description="Permission denied",
        response={
            "type": "object",
            "properties": {
                "detail": {"type": "string"}
            }
        }
    ),
    404: OpenApiResponse(
        description="Resource not found",
        response={
            "type": "object",
            "properties": {
                "detail": {"type": "string"}
            }
        }
    ),
    500: OpenApiResponse(
        description="Server error",
        response={
            "type": "object",
            "properties": {
                "detail": {"type": "string"}
            }
        }
    )
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