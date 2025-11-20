"""
Authentication and Security Settings for the Application
==========================================================

This module contains all authentication-related configurations including:
- JWT settings
- CORS configuration
- CSRF settings
- Password validation
- Social authentication providers
- Security settings
- Session configuration
"""

from datetime import timedelta
from decouple import config

# CORS Settings
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

CORS_ALLOW_CREDENTIALS = True

# CORS Headers for CSRF
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'X-Requested-With',
    'x-forwarded-for',
    'x-forwarded-proto',
    'x-forwarded-host',
    'cache-control',
    'pragma',
]

# Expose headers to the frontend
CORS_EXPOSE_HEADERS = [
    'content-type',
    'x-csrftoken',
]

# CORS Methods
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# CSRF Settings
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

CSRF_COOKIE_NAME = 'csrftoken'
CSRF_HEADER_NAME = 'HTTP_X_CSRFTOKEN'
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript access to CSRF token
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_USE_SESSIONS = False

# Custom user model
AUTH_USER_MODEL = 'accounts.User'

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
]

# Allauth settings - Updated to use non-deprecated format
ACCOUNT_SIGNUP_FIELDS = ['email*', 'password1*', 'password2*']
ACCOUNT_EMAIL_VERIFICATION = 'optional'
ACCOUNT_LOGIN_METHODS = {'email'}
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_USER_MODEL_EMAIL_FIELD = 'email'
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_AUTHENTICATION_METHOD = 'email'
ACCOUNT_EMAIL_REQUIRED = True

# Enhanced Social Authentication Configuration
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'APP': {
            'client_id': '',
            'secret': '',
            'key': ''
        },
        'SCOPE': [
            'profile',
            'email',
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',
        }
    },
    'github': {
        'APP': {
            'client_id': '',
            'secret': '',
        },
        'SCOPE': [
            'user:email',
        ],
    },
    'facebook': {
        'APP': {
            'client_id': '',
            'secret': '',
        },
        'METHOD': 'oauth2',
        'SCOPE': ['email', 'public_profile'],
        'AUTH_PARAMS': {'auth_type': 'reauthenticate'},
        'INIT_PARAMS': {'cookie': True},
        'FIELDS': [
            'id',
            'email',
            'name',
            'first_name',
            'last_name',
            'verified',
            'locale',
            'timezone',
            'link',
            'gender',
            'updated_time',
        ],
        'EXCHANGE_TOKEN': True,
        'VERIFIED_EMAIL': False,
        'VERSION': 'v13.0',
    }
}

# Enhanced Social Authentication Settings - API Only Configuration
SOCIALACCOUNT_QUERY_EMAIL = True
SOCIALACCOUNT_EMAIL_REQUIRED = True
SOCIALACCOUNT_EMAIL_VERIFICATION = 'optional'
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_LOGIN_ON_GET = False
SOCIALACCOUNT_STORE_TOKENS = True
# SOCIALACCOUNT_ADAPTER = 'apps.accounts.adapters.CustomSocialAccountAdapter'
# ACCOUNT_ADAPTER = 'apps.accounts.adapters.CustomAccountAdapter'

# Force API-only social authentication (no template rendering)
SOCIALACCOUNT_EMAIL_AUTHENTICATION = False
SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = False

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Session Configuration
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Changed to False to prevent logout on page navigation

# Security Settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Performance Settings
DB_QUERY_TIMEOUT = 30
API_TIMEOUT = 30
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB

# dj-rest-auth Configuration

REST_AUTH = {
    'LOGIN_SERIALIZER': 'apps.accounts.serializers.CustomLoginSerializer',
    'TOKEN_SERIALIZER': 'dj_rest_auth.serializers.TokenSerializer',
    'JWT_SERIALIZER': 'dj_rest_auth.serializers.JWTSerializer',
    'JWT_SERIALIZER_WITH_EXPIRATION': 'dj_rest_auth.serializers.JWTSerializerWithExpiration',
    'JWT_TOKEN_CLAIMS_SERIALIZER': 'rest_framework_simplejwt.serializers.TokenObtainPairSerializer',
    'USER_DETAILS_SERIALIZER': 'apps.accounts.serializers.UserDetailsSerializer',
    'PASSWORD_RESET_SERIALIZER': 'dj_rest_auth.serializers.PasswordResetSerializer',
    'PASSWORD_RESET_CONFIRM_SERIALIZER': 'dj_rest_auth.serializers.PasswordResetConfirmSerializer',
    'PASSWORD_CHANGE_SERIALIZER': 'dj_rest_auth.serializers.PasswordChangeSerializer',

    'REGISTER_SERIALIZER': 'apps.accounts.serializers.CustomRegisterSerializer',
    'RESEND_EMAIL_VERIFICATION_SERIALIZER': 'dj_rest_auth.registration.serializers.ResendEmailVerificationSerializer',

    'REGISTER_PERMISSION_CLASSES': ('rest_framework.permissions.AllowAny',),

    'TOKEN_MODEL': 'rest_framework.authtoken.models.Token',
    'TOKEN_CREATOR': 'dj_rest_auth.utils.default_create_token',

    'PASSWORD_RESET_USE_SITES_DOMAIN': False,
    'OLD_PASSWORD_FIELD_ENABLED': False,
    'LOGOUT_ON_PASSWORD_CHANGE': True,
    'SESSION_LOGIN': True,
    'USE_JWT': True,

    'JWT_AUTH_COOKIE': 'access',
    'JWT_AUTH_REFRESH_COOKIE': 'refresh',
    'JWT_AUTH_REFRESH_COOKIE_PATH': '/',
    'JWT_AUTH_SECURE': False,
    'JWT_AUTH_HTTPONLY': True,  # Changed to True for security - frontend cannot access httpOnly cookies
    'JWT_AUTH_SAMESITE': 'Lax',
    'JWT_AUTH_RETURN_EXPIRATION': False,
    'JWT_AUTH_COOKIE_USE_CSRF': False,
    'JWT_AUTH_COOKIE_ENFORCE_CSRF_ON_UNAUTHENTICATED': False,
}
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": False,
    "UPDATE_LAST_LOGIN": False,

    "ALGORITHM": "HS256",
    # "SIGNING_KEY": settings.SECRET_KEY,a
    "VERIFYING_KEY": "",
    "AUDIENCE": None,
    "ISSUER": None,
    "JSON_ENCODER": None,
    "JWK_URL": None,
    "LEEWAY": 0,

    "USER_ID_CLAIM_SERIALIZER": str, 

    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "USER_AUTHENTICATION_RULE": "rest_framework_simplejwt.authentication.default_user_authentication_rule",

    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "TOKEN_USER_CLASS": "rest_framework_simplejwt.models.TokenUser",

    "JTI_CLAIM": "jti",

    "SLIDING_TOKEN_REFRESH_EXP_CLAIM": "refresh_exp",
    "SLIDING_TOKEN_LIFETIME": timedelta(minutes=5),
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=1),

    "TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainPairSerializer",
    "TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSerializer",
    "TOKEN_VERIFY_SERIALIZER": "rest_framework_simplejwt.serializers.TokenVerifySerializer",
    "TOKEN_BLACKLIST_SERIALIZER": "rest_framework_simplejwt.serializers.TokenBlacklistSerializer",
    "SLIDING_TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainSlidingSerializer",
    "SLIDING_TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSlidingSerializer",
}