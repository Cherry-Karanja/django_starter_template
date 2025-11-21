"""
API Configuration for the Application
======================================

This module contains all API-related configurations including:
- Django REST Framework settings
- DRF Spectacular (OpenAPI/Swagger) configuration
- API pagination, throttling, and authentication
"""
from decouple import config

# REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'apps.core.authentication.CustomJWTCookieAuthentication',
        'rest_framework.authentication.TokenAuthentication',
        'apps.core.authentication.CSRFExemptSessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.DjangoModelPermissions',
        # 'apps.accounts.permissions.CustomModelPermissions',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.MultiPartParser',
    ],
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_PAGINATION_CLASS': 'apps.core.pagination.StandardResultsSetPagination',
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'content_generation': '60/minute',
        'assessment_generation': '20/minute',
        'agent_request': '100/minute',
        'burst': '10/minute',
    },
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

# DRF Spectacular Settings
SPECTACULAR_SETTINGS = {
    'TITLE': config('SITE_NAME', default='Django') + ' API',
    'DESCRIPTION': 'AI-powered tool that helps institutions automatically generate, review, and manage Assessments while ensuring alignment with curriculum materials.',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'SCHEMA_PATH_PREFIX': '/api/',
    'COMPONENT_SPLIT_REQUEST': True,
    'SORT_OPERATIONS': False,

    # Authentication Configuration for Swagger
    'SECURITY': [
        {'JWTAuth': []},
        {'SessionAuth': []}
    ],
    'SECURITY_DEFINITIONS': {
        'JWTAuth': {
            'type': 'http',
            'scheme': 'bearer',
            'bearerFormat': 'JWT',
            'description': 'Enter JWT token in format: Bearer <token>'
        },
        'SessionAuth': {
            'type': 'apiKey',
            'in': 'cookie',
            'name': 'sessionid'
        }
    },

    # API Contact and License Info
    'CONTACT': {
        'name': config('CONTACT_NAME', default='Django Team'),
        'email': config('CONTACT_EMAIL', default='admin@django.com'),
    },
    'LICENSE': {
        'name': config('LICENSE_NAME', default='MIT License'),
    },

    # Swagger UI Configuration
    'SWAGGER_UI_SETTINGS': {
        'deepLinking': True,
        'persistAuthorization': True,
        'displayOperationId': False,
        'defaultModelsExpandDepth': 2,
        'defaultModelExpandDepth': 2,
        'displayRequestDuration': True,
        'docExpansion': 'none',
        'filter': True,
        'showExtensions': True,
        'showCommonExtensions': True,
        'tryItOutEnabled': True,
    },

    # ReDoc Configuration
    'REDOC_UI_SETTINGS': {
        'nativeScrollbars': True,
        'theme': {
            'typography': {
                'fontSize': '14px',
                'lineHeight': '1.5em',
                'code': {
                    'fontSize': '13px',
                },
            },
            'menu': {
                'backgroundColor': '#fafafa',
            },
        },
    },

    # Schema Generation
    'PREPROCESSING_HOOKS': [],
    'POSTPROCESSING_HOOKS': [],
    'ENUM_NAME_OVERRIDES': {},
    'ENUM_GENERATE_CHOICE_DESCRIPTION': True,

    # Custom operation ID mapping to resolve collisions
    'OPERATION_ID_MAPPING': {
        # Accounts
        'accounts:user_permissions_list': 'accounts_user_permissions_list',
        'accounts:user_permissions_retrieve': 'accounts_user_permissions_retrieve',
    },

    # Tags for grouping endpoints
    'TAGS': [
        # Authentication & User Management
        {
            'name': 'Authentication',
            'description': 'User authentication and registration endpoints including social auth'
        },
        {
            'name': 'Users',
            'description': 'User management and profile operations'
        },
        {
            'name': 'User Profiles',
            'description': 'User profile management and extended user information'
        },
        {
            'name': 'User Role History',
            'description': 'User role change history and audit trail'
        },
        {
            'name': 'User Sessions',
            'description': 'User session management and activity tracking'
        },
        {
            'name': 'Roles',
            'description': 'Role management and permissions configuration'
        },
        {
            'name': 'Login Attempts',
            'description': 'Tracking and management of user login attempts'
        },
        {
            'name': 'Permissions',
            'description': 'Permission management and access control'
        },
        {
            'name': 'Two-Factor Authentication',
            'description': 'Endpoints for managing two-factor authentication setup and verification'
        },

        # Core System
        {
            'name': 'Core',
            'description': 'Core application functionality and health checks'
        },
        {
            'name': 'Statistics',
            'description': 'Statistical data and analytics endpoints'
        },

        # security and notifications
        {
            'name': 'Security',
            'description': 'Security features including rate limiting and audit logging'
        },
        {
            'name': 'Notifications',
            'description': 'User notifications and messaging system'
        },
    ],
}