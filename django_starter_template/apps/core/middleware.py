import uuid
import time
import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.views.decorators.csrf import csrf_exempt
from apps.core.utils import mask_pii

logger = logging.getLogger(__name__)


class APICSRFMiddleware(CsrfViewMiddleware):
    """
    Custom CSRF middleware that exempts API endpoints from CSRF validation
    while still allowing session-based authentication for specific endpoints.
    """

    def process_view(self, request, callback, callback_args, callback_kwargs):
        """
        Override to exempt API endpoints from CSRF validation.
        """
        # Exempt API endpoints from CSRF validation by default, but not admin
        if request.path.startswith('/api/') and not request.path.startswith('/api/v1/admin/'):
            # For DRF endpoints, we rely on JWT authentication primarily
            # Only apply CSRF for specific endpoints that need session auth
            if self._should_apply_csrf(request):
                return super().process_view(request, callback, callback_args, callback_kwargs)
            else:
                return None

        # Apply normal CSRF validation for non-API endpoints
        return super().process_view(request, callback, callback_args, callback_kwargs)

    def _should_apply_csrf(self, request):
        """
        Determine if CSRF should be applied to this API request.
        """
        # Apply CSRF only to specific endpoints that explicitly need it
        csrf_required_endpoints = [
            '/api/core/csrf-token/',  # Authenticated endpoint
        ]

        return any(request.path.startswith(endpoint) for endpoint in csrf_required_endpoints)


class RequestTracingMiddleware(MiddlewareMixin):
    """Add trace ID to all requests"""

    def process_request(self, request):
        request.trace_id = str(uuid.uuid4())
        request.start_time = time.time()


class PerformanceMiddleware(MiddlewareMixin):
    """Monitor request performance"""

    def process_request(self, request):
        request.start_time = time.time()

    def process_response(self, request, response):
        if hasattr(request, 'start_time'):
            duration = time.time() - request.start_time

            # Log slow requests
            if duration > 2.0:
                logger.warning(
                    "Slow request detected",
                    extra={
                        'trace_id': getattr(request, 'trace_id', 'unknown'),
                        'path': request.path,
                        'method': request.method,
                        'duration': duration,
                        'status_code': response.status_code,
                    }
                )

            # Add performance headers
            response['X-Response-Time'] = f"{duration:.3f}s"
            response['X-Trace-ID'] = getattr(request, 'trace_id', 'unknown')

        return response


class ErrorHandlingMiddleware(MiddlewareMixin):
    """Global error handling"""

    def process_exception(self, request, exception):
        logger.error(
            f"Unhandled exception: {str(exception)}",
            extra={
                'trace_id': getattr(request, 'trace_id', 'unknown'),
                'path': request.path,
                'method': request.method,
                'user_id': getattr(request.user, 'id', 'anonymous'),
            },
            exc_info=True
        )

        # Return JSON error for API requests
        if request.path.startswith('/api/'):
            return JsonResponse({
                'error': 'Internal server error',
                'trace_id': getattr(request, 'trace_id', 'unknown'),
            }, status=500)

        return None


class CurrentUserMiddleware(MiddlewareMixin):
    """
    Middleware to set the current user in thread local storage
    for audit field tracking
    """

    def process_request(self, request):
        # Import here to avoid circular imports
        from .signals import set_current_user

        # Set the current user in thread local storage
        if hasattr(request, 'user') and request.user.is_authenticated:
            set_current_user(request.user)
        else:
            set_current_user(None)

    def process_response(self, request, response):
        # Clean up after the request
        from .signals import set_current_user
        set_current_user(None)
        return response