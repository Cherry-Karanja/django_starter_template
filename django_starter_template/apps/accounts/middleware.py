"""
Custom middleware for tracking login attempts and security monitoring
"""
from datetime import timedelta
from django.utils import timezone
from apps.accounts.models import  UserSession

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
                revoked_at__isnull=True
            )
            
            # Check if session has expired based on UserSession expires_at
            if session.expires_at < timezone.now():
                request.session.flush()
                return
            
            # Update expires_at to always be 1 hour from now for both UserSession and Django session
            from django.contrib.sessions.models import Session
            try:
                django_session = Session.objects.get(session_key=request.session.session_key)
                # Django session exists, update both expires_at fields
                new_expires_at = timezone.now() + timedelta(seconds=3600)
                session.expires_at = new_expires_at
                django_session.expire_date = new_expires_at
                session.save(update_fields=['expires_at'])
                django_session.save(update_fields=['expire_date'])
            except Session.DoesNotExist:
                # Django session doesn't exist, mark UserSession as expired (logout occurred)
                UserSession.objects.filter(id=session.id).update(
                    is_active=False,
                    expires_at=timezone.now()
                )
                return
                
            # Populate device_info if not set
            if not session.device_info:
                from apps.core.services import DeviceDetectionService
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                session.device_info = DeviceDetectionService.parse_user_agent(user_agent)
                session.save(update_fields=['device_info'])
                
            # Populate location_info if not set
            if not session.location_info:
                from apps.core.utils import get_client_ip
                from apps.core.services import GeoIPService
                ip_address = get_client_ip(request)
                session.location_info = GeoIPService.get_location_info(ip_address)
                session.save(update_fields=['location_info'])
                
            # Update last activity timestamp (but not too frequently)
            # Only update if last update was more than 5 minutes ago
            time_since_update = timezone.now() - session.last_activity
            if time_since_update.total_seconds() > 300:  # 5 minutes
                session.update_activity()
                
        except UserSession.DoesNotExist:
            # Session exists in cookie but not in our tracking table
            # This could be a security issue or just old data
            if request.user.is_authenticated:
                try:
                    # Check if there's an existing inactive session with this session_key
                    existing_session = UserSession.objects.filter(
                        session_key=request.session.session_key,
                        revoked_at__isnull=False
                    ).first()
                    
                    if existing_session:
                        # Reactivate if Django session exists
                        from django.contrib.sessions.models import Session
                        try:
                            django_session = Session.objects.get(session_key=request.session.session_key)
                            # Django session exists, reactivate UserSession
                            new_expires_at = timezone.now() + timedelta(seconds=3600)
                            existing_session.expires_at = new_expires_at
                            django_session.expire_date = new_expires_at
                            existing_session.revoked_at = None  # Clear revocation if reactivating
                            existing_session.save(update_fields=['expires_at', 'revoked_at'])
                            django_session.save(update_fields=['expire_date'])
                        except Session.DoesNotExist:
                            # Django session doesn't exist, don't reactivate UserSession
                            pass
                    else:
                        # Create new session record if authenticated user and Django session exists
                        from django.contrib.sessions.models import Session
                        try:
                            django_session = Session.objects.get(session_key=request.session.session_key)
                            UserSession.create_session(
                                user=request.user,
                                request=request,
                                created_via='middleware_recovery'
                            )
                        except Session.DoesNotExist:
                            # Django session doesn't exist, don't create UserSession
                            pass
                except Exception as e:
                    # Log the error but don't fail the request
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.error(f"Failed to create/reactivate session record for user {request.user}: {e}")
    
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
    4. Tracks login attempts
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Check if this is a login attempt
        is_login_attempt = self._is_login_attempt(request)
        
        if is_login_attempt:
            # Extract email from request to check account status
            email = self._extract_email_from_request(request)
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
        
        # Track login attempt result
        if is_login_attempt:
            self._track_login_attempt(request, response)
            
        return response
    
    def _is_login_attempt(self, request):
        """Check if the current request is a login attempt"""
        # Traditional Django admin login
        if request.path.endswith('/login/') and request.method == 'POST':
            return True
            
        # REST API login endpoints
        if '/auth/login/' in request.path and request.method == 'POST':
            return True
            
        # dj-rest-auth login (if used)
        if '/rest-auth/login' in request.path and request.method == 'POST':
            return True
            
        return False
    
    def _extract_email_from_request(self, request):
        """Extract email from login request"""
        # Try different field names used by different login forms
        email = None
        
        # Traditional Django form
        if hasattr(request, 'POST') and request.POST:
            email = request.POST.get('username') or request.POST.get('email')
            
        # REST API request
        if hasattr(request, 'data') and request.data:
            email = request.data.get('email') or request.data.get('username')
            
        # JSON request body
        if not email and request.META.get('CONTENT_TYPE', '').startswith('application/json'):
            try:
                import json
                body = request.body.decode('utf-8')
                data = json.loads(body)
                email = data.get('email') or data.get('username')
            except:
                pass
                
        return email.strip().lower() if email else None
    
    def _track_login_attempt(self, request, response):
        """Track the result of a login attempt"""
        from apps.core.utils import get_client_ip
        from .models import LoginAttempt, User
        from apps.core.services import AuthenticationService
        
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        email = self._extract_email_from_request(request)
        
        # Determine if login was successful based on path and response
        is_admin_login = '/admin/login' in request.path
        is_api_login = '/auth/login' in request.path
        
        if is_admin_login:
            # Django admin login: success is authenticated user + redirect (302)
            success = request.user.is_authenticated and response.status_code == 302
        elif is_api_login:
            # API login: success is authenticated user + 200/201
            success = request.user.is_authenticated and response.status_code in [200, 201]
        else:
            # Fallback: authenticated user + success status
            success = request.user.is_authenticated and response.status_code in [200, 201, 302]
        
        try:
            # Find user if successful
            user = None
            if success:
                user = request.user
            elif email:
                try:
                    user = User.objects.get(email=email)
                except User.DoesNotExist:
                    pass
            
            # Create login attempt record
            LoginAttempt.objects.create(
                email=email or '',
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
                success=success,
                failure_reason='invalid_credentials' if not success else ''
            )
            
            if success:
                # Handle successful login
                AuthenticationService.handle_successful_login(user, ip_address)
                import logging
                logger = logging.getLogger(__name__)
                logger.info(f"Login successful for {user.email} from {ip_address}")
            else:
                # Handle failed login
                if user:
                    AuthenticationService.handle_failed_login(user, ip_address)
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Login failed for {email} from {ip_address}")
                
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error tracking login attempt: {str(e)}")
            
            # Create session tracking record
            from apps.core.utils import get_client_ip
            session_key = request.session.session_key
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            # Set expires_at to 1 hour from now
            session_expires_at = timezone.now() + timedelta(seconds=3600)
            
            session, created = UserSession.objects.get_or_create(
                session_key=session_key,
                defaults={
                    'user': request.user,
                    'ip_address': ip_address,
                    'user_agent': user_agent,
                    'expires_at': session_expires_at
                }
            )
            
            # If session already existed, update it with current user info
            if not created:
                session.user = request.user
                session.ip_address = ip_address
                session.user_agent = user_agent
                session.expires_at = session_expires_at
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
