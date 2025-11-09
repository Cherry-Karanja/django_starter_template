from .base import *
from copy import deepcopy
import warnings

# Suppress specific warnings in development
warnings.filterwarnings('ignore', module='dj_rest_auth.registration.serializers')
warnings.filterwarnings('ignore', message='.*USERNAME_REQUIRED is deprecated.*')
warnings.filterwarnings('ignore', message='.*EMAIL_REQUIRED is deprecated.*')
warnings.filterwarnings('ignore', message='.*AUTHENTICATION_METHOD is deprecated.*')
# Suppress drf-spectacular operationId collision warnings
warnings.filterwarnings('ignore', message='.*operationId .* has collisions.*')

# Override base settings for development
DEBUG = True

# Allow all hosts in development
ALLOWED_HOSTS = ['*']

# Database for development - using SQLite for easier setup
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Email backend for development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Use local memory cache in development (no Redis required)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}

# Additional debug tools
import sys
if 'test' not in sys.argv:
    INSTALLED_APPS += [
        'debug_toolbar',
        'django_browser_reload',
    ]

    MIDDLEWARE += [
        'debug_toolbar.middleware.DebugToolbarMiddleware',
        'django_browser_reload.middleware.BrowserReloadMiddleware',
    ]

INTERNAL_IPS = ['127.0.0.1', 'localhost']

# Celery Configuration
# NOTE: Set to False to use actual Celery workers (required for async processing)
# Set to True only for testing/debugging to execute tasks synchronously
CELERY_TASK_ALWAYS_EAGER = False  # Changed from True - use actual Celery workers
CELERY_TASK_EAGER_PROPAGATES = False  # Don't propagate exceptions to caller

# CORS settings for development
CORS_ALLOW_ALL_ORIGINS = True

# Django Debug Toolbar configuration - Reduce verbosity
DEBUG_TOOLBAR_CONFIG = {
    'SHOW_TOOLBAR_CALLBACK': lambda request: DEBUG,
    'IS_RUNNING_TESTS': False,
    'RENDER_PANELS': True,
    'SHOW_TEMPLATE_CONTEXT': True,
    'ENABLE_STACKTRACES': True,
    # Disable problematic panels that cause serialization issues
    'DISABLE_PANELS': [
        'debug_toolbar.panels.cache.CachePanel',  # Disable cache panel to avoid serialization logs
        'debug_toolbar.panels.staticfiles.StaticFilesPanel',  # Reduce noise
        'debug_toolbar.panels.profiling.ProfilingPanel',  # Disable profiling panel to avoid conflicts
    ],
    'EXTRA_SIGNALS': [],
    # Reduce console output
    'CONSOLE_LOG_LEVEL': 'WARNING',
}

# Development-specific logging - Reduce verbosity
LOGGING = deepcopy(LOGGING)
LOGGING['root']['level'] = 'DEBUG'  # Changed from DEBUG to INFO
LOGGING['loggers']['apps']['level'] = 'DEBUG'  # Changed from DEBUG to INFO

# Silence debug toolbar logs
LOGGING['loggers']['debug_toolbar'] = {
    'handlers': ['console'],
    'level': 'WARNING',  # Only show warnings and errors
    'propagate': False,
}

# Silence dj-rest-auth deprecation warnings
LOGGING['loggers']['dj_rest_auth'] = {
    'handlers': ['console'], 
    'level': 'ERROR',  # Only show errors, not warnings
    'propagate': False,
}

# Reduce Django server logs verbosity
LOGGING['loggers']['django.server'] = {
    'handlers': ['console'],
    'level': 'WARNING',  # Only show warnings and errors
    'propagate': False,
}

# Reduce cache serialization warnings
LOGGING['loggers']['django.core.cache'] = {
    'handlers': ['console'],
    'level': 'WARNING',
    'propagate': False,
}

# Configure drf-spectacular to be quieter about operationId collisions
SPECTACULAR_SETTINGS = SPECTACULAR_SETTINGS.copy()
SPECTACULAR_SETTINGS['COMPONENT_SPLIT_REQUEST'] = True
SPECTACULAR_SETTINGS['POSTPROCESSING_HOOKS'] = []
# Use a custom function for operationId generation to avoid collisions
SPECTACULAR_SETTINGS['OPERATION_ID_MAPPING'] = {}

# Disable HTTPS requirements in development
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# CSRF settings for development
CSRF_COOKIE_DOMAIN = None
CSRF_COOKIE_PATH = '/'

# ==================== AI SERVICES CONFIGURATION ====================

# Direct RAG Client (Monolith Mode) - No external HTTP calls needed
USE_DIRECT_RAG_CLIENT = True  # Use direct Python imports instead of HTTP calls

# LLM Configuration
LLM_TIMEOUT_SECONDS = int(os.getenv('LLM_TIMEOUT_SECONDS', '600'))
LLM_MAX_RETRIES = int(os.getenv('LLM_MAX_RETRIES', '5'))
LLM_BASE_DELAY = float(os.getenv('LLM_BASE_DELAY', '2.0'))

# Google GenAI API Key
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '')

# Default Models
DEFAULT_CHAT_PROVIDER = os.getenv('DEFAULT_CHAT_PROVIDER', 'gemini')
DEFAULT_CHAT_MODEL = os.getenv('DEFAULT_CHAT_MODEL', 'gemini-2.0-flash-exp')
DEFAULT_EMBEDDING_PROVIDER = os.getenv('DEFAULT_EMBEDDING_PROVIDER', 'vertex_ai')  # Use Vertex AI
DEFAULT_EMBEDDING_MODEL = os.getenv('DEFAULT_EMBEDDING_MODEL', 'gemini-embedding-001')  # 768 dimensions

# ==================== GOOGLE VERTEX AI CONFIGURATION ====================
# For Google VM - ADC Authentication

# Google Cloud Project Configuration
GOOGLE_CLOUD_PROJECT = os.getenv('GOOGLE_CLOUD_PROJECT', 'orbital-expanse-468309-m5')
GOOGLE_CLOUD_LOCATION = os.getenv('GOOGLE_CLOUD_LOCATION', 'us-central1')

# Vertex AI Models
VERTEX_AI_MODEL = os.getenv('VERTEX_AI_MODEL', 'gemini-2.0-flash-exp')
VERTEX_AI_QA_MODEL = os.getenv('VERTEX_AI_QA_MODEL', 'gemini-2.5-pro')
VERTEX_AI_EMBEDDING_MODEL = os.getenv('VERTEX_AI_EMBEDDING_MODEL', 'gemini-embedding-001')  # 768 dimensions

# Model Parameters
VERTEX_AI_TEMPERATURE = float(os.getenv('VERTEX_AI_TEMPERATURE', '0.7'))
VERTEX_AI_TOP_P = float(os.getenv('VERTEX_AI_TOP_P', '0.95'))
VERTEX_AI_TOP_K = int(os.getenv('VERTEX_AI_TOP_K', '40'))
VERTEX_AI_MAX_OUTPUT_TOKENS = int(os.getenv('VERTEX_AI_MAX_OUTPUT_TOKENS', '8192'))

# Safety Settings
VERTEX_AI_HARM_BLOCK_THRESHOLD = os.getenv('VERTEX_AI_HARM_BLOCK_THRESHOLD', 'BLOCK_MEDIUM_AND_ABOVE')

# Rate Limiting
VERTEX_AI_MAX_REQUESTS_PER_MINUTE = int(os.getenv('VERTEX_AI_MAX_REQUESTS_PER_MINUTE', '60'))
VERTEX_AI_MAX_TOKENS_PER_MINUTE = int(os.getenv('VERTEX_AI_MAX_TOKENS_PER_MINUTE', '100000'))

# Agent Configuration
AGENT_ROOT_NAME = os.getenv('AGENT_ROOT_NAME', 'content_generation_system')
AGENT_DEBUG_MODE = os.getenv('AGENT_DEBUG_MODE', 'true').lower() == 'true'
AGENT_ENABLE_TRACING = os.getenv('AGENT_ENABLE_TRACING', 'true').lower() == 'true'

# Use Vertex AI instead of API Key (set to true on Google VM)
USE_VERTEX_AI = os.getenv('USE_VERTEX_AI', 'true').lower() == 'true'

# Tavily API Key (for web search)
TAVILY_API_KEY = os.getenv('TAVILY_API_KEY', '')

# Image Generation
IMAGE_GENERATION_LOCATION = os.getenv('IMAGE_GENERATION_LOCATION', 'global')
IMAGE_GENERATION_MODEL = os.getenv('IMAGE_GENERATION_MODEL', 'gemini-2.5-flash-image')

# Agent Configuration
MAX_CONCURRENT_AGENTS = int(os.getenv('MAX_CONCURRENT_AGENTS', '5'))
AGENT_TIMEOUT = int(os.getenv('AGENT_TIMEOUT', '300'))

# Content Limits
MAX_DOCUMENT_SIZE_MB = int(os.getenv('MAX_DOCUMENT_SIZE_MB', '50'))
MAX_SYNTHESIS_LENGTH = int(os.getenv('MAX_SYNTHESIS_LENGTH', '50000'))

# ==================== CONTENT GENERATION RATE LIMITING ====================
# Rate limiting for content generation endpoints
# Uses Django's existing Redis cache from base.py settings

RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', '60'))

# DRF Throttle rates for content generation
CONTENT_GENERATION_THROTTLE_RATES = {
    'content_generation': f'{RATE_LIMIT_PER_MINUTE}/minute',      # General content generation
    'assessment_generation': '20/minute',                          # Assessment generation (resource-intensive)
    'agent_request': '100/minute',                                 # Agent requests
    'burst': '10/minute',                                          # Burst protection (rapid consecutive requests)
}

# ==================== AUTORELOAD CONFIGURATION ====================
# Prevent Django autoreload from restarting Celery workers
# This ensures Celery tasks persist across Django code changes
import fnmatch

def skip_celery_files(file_path):
    """
    Skip Celery-related files from Django autoreload to prevent worker restarts.
    This allows Celery workers to maintain task state and avoid interruptions.
    """
    celery_patterns = [
        '**/celery.py',
        '**/tasks.py',
        '**/apps.py',  # May contain Celery beat registrations
        '**/services/**',  # Service layer changes shouldn't restart workers
        '**/management/commands/**',  # Management commands
    ]

    for pattern in celery_patterns:
        if fnmatch.fnmatch(file_path, pattern):
            return True
    return False

# Configure autoreload to skip Celery files
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB

# Use custom autoreload filter to prevent Celery worker restarts
try:
    from django.utils import autoreload
    autoreload.skip_reloader_filter = skip_celery_files
except ImportError:
    # autoreload module not available in some Django versions
    pass
