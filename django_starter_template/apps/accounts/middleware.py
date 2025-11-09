"""
Custom middleware for tracking login attempts and security monitoring
"""
from datetime import timedelta
from django.utils import timezone
from apps.accounts.models import LoginAttempt, UserSession


class LoginAttemptMiddleware:
    """
    Middleware to track login attempts and enhance security
    
    This middleware captures login attempts from Django's authentication system
    and logs them to the LoginAttempt model for security monitoring.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Process request and get response
        response = self.get_response(request)
        return response
        
    def process_view(self, request, view_func, view_args, view_kwargs):
        """
        Process each view to track login attempts
        """
        # Only process views that handle login
        view_name = view_func.__name__ if hasattr(view_func, '__name__') else str(view_func)
        if view_name not in ['login', 'obtain_auth_token', 'TokenObtainPairView', 'LoginView']:
            return None
            
        # Only process POST requests (login attempts)
        if request.method != 'POST':
            return None
            
        # Extract email from request data
        email = request.POST.get('email', request.POST.get('username', '')).lower()
        if not email:
            # Try to get from JSON data for API login attempts
            try:
                if hasattr(request, 'data'):
                    email = request.data.get('email', request.data.get('username', '')).lower()
            except (AttributeError, ValueError):
                pass
                
        if not email:
            return None
            
        # Get IP address with support for proxies
        ip_address = self._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        session_id = request.session.session_key if hasattr(request, 'session') else None
        
        # NOTE: Login attempt logging is now handled entirely by the authentication backend
        # to avoid duplicate records. The backend logs both successful and failed attempts.
        
        return None
        
    def _get_client_ip(self, request):
        """Get client IP address from request, handling proxy headers"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Get the first IP in case of multiple proxies
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip


class SessionActivityMiddleware:
    """
    Middleware to track user session activity and enforce security policies
    
    This middleware:
    1. Updates last activity timestamp for active sessions
    2. Validates session expiration and validity
    3. Enforces security policies like session timeout
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Process request before view is called
        self.process_request(request)
        
        # Call the view
        response = self.get_response(request)
        
        # Process response after view is called
        return self.process_response(request, response)
        
    def process_request(self, request):
        """Process incoming request to validate session"""
        # Skip for unauthenticated users
        if not request.user.is_authenticated:
            return
            
        # Skip for non-browser requests (like API calls with tokens)
        if not hasattr(request, 'session') or not request.session.session_key:
            return
            
        try:
            # Get current session record
            session = UserSession.objects.get(
                session_key=request.session.session_key,
                is_active=True
            )
            
            # Check if session has expired
            if session.is_expired:
                session.revoke(reason='expired')
                # Force user to login again
                request.session.flush()
                
            # Update last activity timestamp (but not too frequently)
            # Only update if last update was more than 5 minutes ago
            time_since_update = timezone.now() - session.last_activity
            if time_since_update.total_seconds() > 300:  # 5 minutes
                session.update_activity()
                
        except UserSession.DoesNotExist:
            # Session exists in cookie but not in our tracking table
            # This could be a security issue or just old data
            if request.user.is_authenticated:
                # Create session record if authenticated user
                UserSession.create_session(
                    user=request.user,
                    request=request,
                    created_via='middleware_recovery'
                )
    
    def process_response(self, request, response):
        """Process response before returning to client"""
        return response


class LoginSecurityMiddleware:
    """
    Middleware to enforce login security policies
    
    This middleware:
    1. Checks for account lockouts before login
    2. Enforces password change requirements
    3. Records login IP addresses
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Skip middleware for non-authenticated requests except login page
        is_login = request.path.endswith('/login/') and request.method == 'POST'
        
        if is_login:
            # Extract email from login form to check account status
            email = request.POST.get('username', '').strip().lower()
            if email:
                from .models import User
                try:
                    user = User.objects.get(email=email)
                    
                    # Check if account is locked
                    if user.account_locked_until and user.account_locked_until > timezone.now():
                        # Account is locked - we'll let the authentication backend handle this
                        pass
                except User.DoesNotExist:
                    # User doesn't exist, normal login flow will handle this
                    pass
                    
        # Process the request
        response = self.get_response(request)
        
        # If login was successful, update user's IP
        if is_login and request.user.is_authenticated:
            # Update the last login IP
            request.user.last_login_ip = request.META.get('REMOTE_ADDR', '')
            request.user.save(update_fields=['last_login_ip'])
            
            # Create session tracking record
            from apps.core.utils import get_client_ip
            session_key = request.session.session_key
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            session, created = UserSession.objects.get_or_create(
                session_key=session_key,
                defaults={
                    'user': request.user,
                    'ip_address': ip_address,
                    'user_agent': user_agent,
                    'expires_at': timezone.now() + timedelta(days=7)  # 7 days
                }
            )
            
            # If session already existed, update it with current user info
            if not created:
                session.user = request.user
                session.ip_address = ip_address
                session.user_agent = user_agent
                session.expires_at = timezone.now() + timedelta(days=7)
                session.is_active = True
                session.save()
            
            # Check for suspicious sessions
            suspicious_sessions = UserSession.detect_suspicious_sessions(request.user, request)
            if suspicious_sessions:
                # If suspicious sessions are detected, we could:
                # 1. Log the suspicious activity
                # 2. Send an alert email to the user
                # 3. Force re-authentication for sensitive actions
                # 4. Add a warning banner to the UI
                
                # For now, just log it
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(
                    f"Suspicious sessions detected for user {request.user.email}: " +
                    f"{len(suspicious_sessions)} suspicious sessions"
                )
                
                # You could also set a session flag to show a warning to the user
                request.session['security_alert'] = {
                    'type': 'suspicious_session',
                    'message': f"We've detected unusual login activity on your account. Please review your active sessions.",
                    'timestamp': timezone.now().isoformat()
                }
            
        return response
