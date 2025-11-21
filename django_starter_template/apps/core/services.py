from django.db import models
from user_agents import parse
from geoip2 import database
from geoip2.errors import AddressNotFoundError
from apps.security.models import AuditLog
from django_otp.plugins.otp_totp.models import TOTPDevice
from apps.accounts.models import  UserSession, LoginAttempt
from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
import qrcode
import io
import base64
import logging

logger = logging.getLogger('core.services')

class AuthenticationService:
    """Service class for authentication-related operations"""

    @staticmethod
    def track_login_attempt(email, ip_address, user_agent, success=True):
        """Track login attempt"""
        try:
            LoginAttempt.objects.create(
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=success
            )
            
            # Log to audit
            event_type = AuditLog.EventType.LOGIN if success else AuditLog.EventType.FAILED_LOGIN
            severity = AuditLog.Severity.LOW if success else AuditLog.Severity.MEDIUM
            
            AuditLog.objects.create(
                user=None,  # User not known at this point for failed logins
                event_type=event_type,
                severity=severity,
                description=f"Login attempt for {email}",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            
        except Exception as e:
            logger.error(f"Error tracking login attempt: {str(e)}")

    @staticmethod
    def handle_failed_login(user, ip_address):
        """Handle failed login attempt"""
        try:
            user.increment_failed_login_attempts()
            logger.warning(f"Failed login attempt for {user.email} from {ip_address}")
        except Exception as e:
            logger.error(f"Error handling failed login for {user.email}: {str(e)}")

    @staticmethod
    def handle_successful_login(user, ip_address):
        """Handle successful login"""
        try:
            # Reset failed login attempts
            user.reset_failed_login_attempts()
            user.last_login_ip = ip_address
            user.save(update_fields=['last_login_ip'])

            # Log successful login to audit
            AuditLog.objects.create(
                user=user,
                event_type=AuditLog.EventType.LOGIN,
                severity=AuditLog.Severity.LOW,
                description=f"Successful login for {user.email}",
                ip_address=ip_address,
            )

            logger.info(f"Successful login for {user.email}")
        except Exception as e:
            logger.error(f"Error handling successful login for {user.email}: {str(e)}")

    @staticmethod
    def is_account_locked(user):
        """Check if user account is locked"""
        return user.is_account_locked()

    @staticmethod
    def create_user_session(user, session_key, ip_address, user_agent, expires_at=None):
        """Create user session record"""
        try:
            # Expire old sessions if too many active
            active_sessions = UserSession.objects.filter(
                user=user,
                is_active=True,
                expires_at__gt=timezone.now()
            ).order_by('-last_activity')

            # Keep only the most recent sessions
            max_sessions = getattr(settings, 'MAX_CONCURRENT_SESSIONS', 5)
            if active_sessions.count() >= max_sessions:
                # Expire oldest sessions
                sessions_to_expire = active_sessions[max_sessions-1:]
                sessions_to_expire.update(is_active=False)

            # Create new session
            if expires_at is None:
                expires_at = timezone.now() + timedelta(days=7)  # 7 days fallback
            
            session = UserSession.objects.create(
                user=user,
                session_key=session_key,
                ip_address=ip_address,
                user_agent=user_agent,
                expires_at=expires_at
            )

            return session

        except Exception as e:
            logger.error(f"Error creating user session: {str(e)}")
            return None

    @staticmethod
    def expire_user_sessions(user, exclude_session_key=None):
        """Expire all sessions for a user except the current one"""
        try:
            sessions = UserSession.objects.filter(
                user=user,
                is_active=True
            )

            if exclude_session_key:
                sessions = sessions.exclude(session_key=exclude_session_key)

            expired_count = sessions.update(is_active=False)
            return expired_count

        except Exception as e:
            logger.error(f"Error expiring user sessions: {str(e)}")
            return 0


class DeviceDetectionService:
    """Service class for device detection from user agent strings"""

    @staticmethod
    def parse_user_agent(user_agent_string):
        """Parse user agent string and return device information"""
        try:
            if not user_agent_string:
                return {
                    'browser': 'Unknown',
                    'browser_version': 'Unknown',
                    'os': 'Unknown',
                    'os_version': 'Unknown',
                    'device': 'Unknown',
                    'device_brand': 'Unknown',
                    'device_model': 'Unknown',
                    'is_mobile': False,
                    'is_tablet': False,
                    'is_pc': True,
                    'is_bot': False
                }

            user_agent = parse(user_agent_string)

            return {
                'browser': user_agent.browser.family,
                'browser_version': str(user_agent.browser.version[0]) if user_agent.browser.version else 'Unknown',
                'os': user_agent.os.family,
                'os_version': str(user_agent.os.version[0]) if user_agent.os.version else 'Unknown',
                'device': user_agent.device.family,
                'device_brand': user_agent.device.brand,
                'device_model': user_agent.device.model,
                'is_mobile': user_agent.is_mobile,
                'is_tablet': user_agent.is_tablet,
                'is_pc': user_agent.is_pc,
                'is_bot': user_agent.is_bot
            }

        except Exception as e:
            logger.error(f"Error parsing user agent '{user_agent_string}': {str(e)}")
            return {
                'browser': 'Unknown',
                'browser_version': 'Unknown',
                'os': 'Unknown',
                'os_version': 'Unknown',
                'device': 'Unknown',
                'device_brand': 'Unknown',
                'device_model': 'Unknown',
                'is_mobile': False,
                'is_tablet': False,
                'is_pc': True,
                'is_bot': False
            }

    @staticmethod
    def get_device_summary(user_agent_string):
        """Get a human-readable device summary"""
        device_info = DeviceDetectionService.parse_user_agent(user_agent_string)

        if device_info['is_bot']:
            return "Bot/Crawler"
        elif device_info['is_mobile']:
            return f"{device_info['device_brand']} {device_info['device_model']} (Mobile)"
        elif device_info['is_tablet']:
            return f"{device_info['device_brand']} {device_info['device_model']} (Tablet)"
        else:
            return f"{device_info['browser']} on {device_info['os']} (Desktop)"


class GeoIPService:
    """Service class for IP geolocation using GeoIP2"""

    # Path to GeoLite2 City database (needs to be downloaded separately)
    GEOIP_DATABASE_PATH = getattr(settings, 'GEOIP_DATABASE_PATH', 'GeoLite2-City.mmdb')

    @staticmethod
    def get_location_info(ip_address):
        """Get geographic location information for an IP address"""
        try:
            if not ip_address or ip_address in ['127.0.0.1', '::1', 'localhost']:
                return {
                    'country': 'Local',
                    'country_code': 'XX',
                    'city': 'Local',
                    'region': 'Local',
                    'latitude': None,
                    'longitude': None,
                    'timezone': None,
                    'is_local': True
                }

            # Check if database file exists
            import os
            if not os.path.exists(GeoIPService.GEOIP_DATABASE_PATH):
                logger.warning(f"GeoIP database not found at {GeoIPService.GEOIP_DATABASE_PATH}. Using default location.")
                return GeoIPService._get_default_location(ip_address)

            # Query the database
            with database.Reader(GeoIPService.GEOIP_DATABASE_PATH) as reader:
                response = reader.city(ip_address)

                return {
                    'country': response.country.name,
                    'country_code': response.country.iso_code,
                    'city': response.city.name,
                    'region': response.subdivisions.most_specific.name if response.subdivisions else None,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'timezone': response.location.time_zone,
                    'is_local': False
                }

        except AddressNotFoundError:
            logger.info(f"IP address {ip_address} not found in GeoIP database")
            return GeoIPService._get_default_location(ip_address)
        except Exception as e:
            logger.error(f"Error getting location for IP {ip_address}: {str(e)}")
            return GeoIPService._get_default_location(ip_address)

    @staticmethod
    def _get_default_location(ip_address):
        """Return default location info when GeoIP lookup fails"""
        return {
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'region': 'Unknown',
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'is_local': False
        }

    @staticmethod
    def is_suspicious_location(current_location, previous_locations, max_distance_km=500):
        """
        Check if current location is suspicious compared to previous locations

        Args:
            current_location: Dict with latitude/longitude
            previous_locations: List of dicts with latitude/longitude
            max_distance_km: Maximum allowed distance in km

        Returns:
            bool: True if suspicious
        """
        if not current_location.get('latitude') or not current_location.get('longitude'):
            return False

        try:
            from math import radians, sin, cos, sqrt, atan2

            def haversine_distance(lat1, lon1, lat2, lon2):
                """Calculate distance between two points on Earth"""
                R = 6371  # Earth's radius in km

                dlat = radians(lat2 - lat1)
                dlon = radians(lon2 - lon1)

                a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
                c = 2 * atan2(sqrt(a), sqrt(1-a))

                return R * c

            current_lat = current_location['latitude']
            current_lon = current_location['longitude']

            for prev_loc in previous_locations:
                if prev_loc.get('latitude') and prev_loc.get('longitude'):
                    distance = haversine_distance(
                        current_lat, current_lon,
                        prev_loc['latitude'], prev_loc['longitude']
                    )
                    if distance > max_distance_km:
                        return True

            return False

        except Exception as e:
            logger.error(f"Error calculating location distance: {str(e)}")
            return False


class RiskScoringService:
    """Service class for advanced risk assessment and scoring"""

    @staticmethod
    def assess_session_risk(session):
        """Perform comprehensive risk assessment for a session"""
        risk_factors = {
            'new_device': False,
            'new_location': False,
            'unusual_time': False,
            'bot_activity': False,
            'recent_failures': False,
            'multiple_sessions': False
        }
        
        score = 0
        
        # Check for new device
        if session.device_info:
            user_sessions = UserSession.objects.filter(
                user=session.user,
                device_info__isnull=False
            ).exclude(id=session.id)
            
            device_known = any(
                s.device_info.get('device_brand') == session.device_info.get('device_brand') and
                s.device_info.get('device_model') == session.device_info.get('device_model')
                for s in user_sessions if s.device_info
            )
            
            if not device_known:
                risk_factors['new_device'] = True
                score += 30
        
        # Check for new location
        if session.location_info:
            user_sessions = UserSession.objects.filter(
                user=session.user,
                location_info__isnull=False
            ).exclude(id=session.id)
            
            location_known = any(
                s.location_info.get('country_code') == session.location_info.get('country_code')
                for s in user_sessions if s.location_info
            )
            
            if not location_known:
                risk_factors['new_location'] = True
                score += 25
        
        # Check for unusual login time
        login_hour = session.created_at.hour
        if 2 <= login_hour <= 6:
            risk_factors['unusual_time'] = True
            score += 15
        
        # Check for bot activity
        if session.device_info and session.device_info.get('is_bot'):
            risk_factors['bot_activity'] = True
            score += 20
        
        # Check for recent login failures
        from apps.accounts.models import LoginAttempt
        recent_failures = LoginAttempt.objects.filter(
            email=session.user.email,
            success=False,
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).count()
        
        if recent_failures > 3:
            risk_factors['recent_failures'] = True
            score += 10
        
        # Check for multiple concurrent sessions
        active_sessions = UserSession.objects.filter(
            user=session.user,
            is_active=True,
            expires_at__gt=timezone.now()
        ).exclude(id=session.id).count()
        
        if active_sessions > 2:
            risk_factors['multiple_sessions'] = True
            score += 10
        
        return {
            'score': min(score, 100),
            'risk_factors': risk_factors,
            'risk_level': RiskScoringService._get_risk_level(score)
        }
    
    @staticmethod
    def _get_risk_level(score):
        """Determine risk level based on score"""
        if score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'
    
    @staticmethod
    def get_user_risk_profile(user):
        """Get comprehensive risk profile for a user"""
        sessions = UserSession.objects.filter(user=user).order_by('-created_at')[:10]
        
        risk_history = []
        for session in sessions:
            assessment = RiskScoringService.assess_session_risk(session)
            risk_history.append({
                'session_id': session.id,
                'created_at': session.created_at,
                'score': assessment['score'],
                'risk_level': assessment['risk_level'],
                'factors': assessment['risk_factors']
            })
        
        # Calculate average risk score
        if risk_history:
            avg_score = sum(item['score'] for item in risk_history) / len(risk_history)
        else:
            avg_score = 0
        
        return {
            'user_id': user.id,
            'average_risk_score': avg_score,
            'overall_risk_level': RiskScoringService._get_risk_level(avg_score),
            'recent_sessions': risk_history
        }


class RateLimitService:
    """Service class for managing rate limits"""

    @staticmethod
    def check_rate_limit(identifier, limit_type, endpoint, max_requests, window_seconds):
        """Check if rate limit is exceeded for an identifier"""
        from django.utils import timezone
        from datetime import timedelta
        from apps.security.models import RateLimit

        now = timezone.now()
        window_start = now - timedelta(seconds=window_seconds)

        # Get or create rate limit record
        rate_limit, created = RateLimit.objects.get_or_create(
            limit_type=limit_type,
            identifier=identifier,
            endpoint=endpoint,
            window_start__gte=window_start,
            defaults={
                'window_start': window_start,
                'window_end': now + timedelta(seconds=window_seconds),
                'request_count': 0
            }
        )

        # If record is from previous window, reset
        if rate_limit.window_start < window_start:
            rate_limit.window_start = window_start
            rate_limit.window_end = now + timedelta(seconds=window_seconds)
            rate_limit.request_count = 0
            rate_limit.is_blocked = False
            rate_limit.blocked_until = None
            rate_limit.save()

        # Check if currently blocked
        if rate_limit.is_blocked and (rate_limit.blocked_until and rate_limit.blocked_until > now):
            return False, rate_limit.blocked_until

        # Increment request count
        rate_limit.request_count += 1

        # Check if limit exceeded
        if rate_limit.request_count > max_requests:
            # Block the identifier
            rate_limit.is_blocked = True
            rate_limit.blocked_until = now + timedelta(minutes=15)
            rate_limit.save()
            return False, rate_limit.blocked_until

        rate_limit.save()
        return True, None

    @staticmethod
    def get_rate_limit_status(identifier, limit_type, endpoint):
        """Get current rate limit status for an identifier"""
        from apps.security.models import RateLimit
        from django.utils import timezone

        try:
            rate_limit = RateLimit.objects.get(
                limit_type=limit_type,
                identifier=identifier,
                endpoint=endpoint,
                is_blocked=True,
                blocked_until__gt=timezone.now()
            )
            return {
                'is_blocked': True,
                'blocked_until': rate_limit.blocked_until,
                'request_count': rate_limit.request_count
            }
        except RateLimit.DoesNotExist:
            return {
                'is_blocked': False,
                'blocked_until': None,
                'request_count': 0
            }

    @staticmethod
    def clear_rate_limit(identifier, limit_type, endpoint):
        """Clear rate limit for an identifier"""
        from apps.security.models import RateLimit

        RateLimit.objects.filter(
            limit_type=limit_type,
            identifier=identifier,
            endpoint=endpoint
        ).update(
            is_blocked=False,
            blocked_until=None,
            request_count=0
        )

    @staticmethod
    def get_rate_limit_stats():
        """Get overall rate limiting statistics"""
        from apps.security.models import RateLimit
        from django.utils import timezone
        from django.db.models import Count, Sum

        now = timezone.now()

        stats = RateLimit.objects.filter(
            window_start__gte=now - timedelta(hours=24)
        ).aggregate(
            total_requests=Sum('request_count'),
            blocked_count=Count('id', filter=models.Q(is_blocked=True)),
            active_blocks=Count('id', filter=models.Q(is_blocked=True, blocked_until__gt=now))
        )

        return stats


class AuditLogService:
    """Service class for centralized audit logging"""

    @staticmethod
    def log_event(user, event_type, severity, description, ip_address=None, user_agent=None, 
                  session_key=None, request_path=None, request_method=None, request_data=None, 
                  response_status=None, additional_data=None):
        """Log an audit event"""
        try:
            AuditLog.objects.create(
                user=user,
                event_type=event_type,
                severity=severity,
                description=description,
                ip_address=ip_address,
                user_agent=user_agent,
                session_key=session_key,
                request_path=request_path,
                request_method=request_method,
                request_data=request_data,
                response_status=response_status,
                additional_data=additional_data
            )
        except Exception as e:
            logger.error(f"Error logging audit event: {str(e)}")

    @staticmethod
    def log_security_event(user, event_type, description, request=None, additional_data=None):
        """Log a security-related event"""
        ip_address = None
        user_agent = None
        session_key = None
        request_path = None
        request_method = None
        
        if request:
            from apps.core.utils import get_client_ip
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT')
            session_key = request.session.session_key if hasattr(request, 'session') else None
            request_path = request.path
            request_method = request.method

        severity = AuditLog.Severity.MEDIUM  # Default for security events
        
        AuditLogService.log_event(
            user=user,
            event_type=event_type,
            severity=severity,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            session_key=session_key,
            request_path=request_path,
            request_method=request_method,
            additional_data=additional_data
        )

    @staticmethod
    def get_audit_trail(user=None, event_type=None, start_date=None, end_date=None, limit=100):
        """Get audit trail with filters"""
        from django.utils import timezone
        from datetime import timedelta
        
        queryset = AuditLog.objects.all()
        
        if user:
            queryset = queryset.filter(user=user)
        
        if event_type:
            queryset = queryset.filter(event_type=event_type)
        
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        elif not end_date:
            # Default to last 30 days if no dates specified
            queryset = queryset.filter(timestamp__gte=timezone.now() - timedelta(days=30))
        
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)
        
        return queryset.order_by('-timestamp')[:limit]

    @staticmethod
    def get_security_summary(start_date=None, end_date=None):
        """Get security events summary"""
        from django.utils import timezone
        from datetime import timedelta
        from django.db.models import Count
        
        if not start_date:
            start_date = timezone.now() - timedelta(days=7)
        if not end_date:
            end_date = timezone.now()
        
        security_events = AuditLog.objects.filter(
            timestamp__gte=start_date,
            timestamp__lte=end_date,
            event_type__in=[
                AuditLog.EventType.FAILED_LOGIN,
                AuditLog.EventType.SECURITY_VIOLATION,
                AuditLog.EventType.UNAUTHORIZED_ACCESS,
                AuditLog.EventType.SUSPICIOUS_ACTIVITY
            ]
        ).values('event_type').annotate(count=Count('id'))
        
        return list(security_events)


class TwoFactorAuthService:
    
    """Service class for two-factor authentication operations"""

    @staticmethod
    def setup_2fa(user, device_name="default"):
        """Set up 2FA for a user and return QR code data"""
        if user.is_otp_enabled():
            raise ValueError("2FA is already enabled for this user")

        # Create TOTP device
        device = user.enable_otp(device_name)

        # Generate provisioning URI for QR code
        provisioning_uri = device.config_url

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        # Create QR code image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

        return {
            'device_id': device.id,
            'provisioning_uri': provisioning_uri,
            'qr_code': qr_code_base64,
            'secret': device.bin_key  # For backup/manual entry
        }

    @staticmethod
    def verify_2fa_setup(user, token):
        """Verify 2FA setup with a token and confirm the device"""
        if not user.otp_device or user.otp_device.confirmed:
            return False

        # Verify the token
        if user.otp_device.verify_token(token):
            # Confirm the device
            user.otp_device.confirmed = True
            user.otp_device.save()

            # Generate backup codes
            backup_codes = user.generate_backup_codes()

            return {
                'success': True,
                'backup_codes': backup_codes
            }

        return {'success': False}

    @staticmethod
    def verify_2fa_token(user, token):
        """Verify a 2FA token during login"""
        if not user.is_otp_enabled():
            return True  # No 2FA required

        if not user.otp_device or not user.otp_device.confirmed:
            return False

        return user.otp_device.verify_token(token)

    @staticmethod
    def disable_2fa(user):
        """Disable 2FA for a user"""
        user.disable_otp()
        return True

    @staticmethod
    def regenerate_backup_codes(user):
        """Regenerate backup codes for a user"""
        if not user.is_otp_enabled():
            raise ValueError("2FA must be enabled to regenerate backup codes")

        backup_codes = user.generate_backup_codes()
        return backup_codes

    @staticmethod
    def get_2fa_status(user):
        """Get 2FA status for a user"""
        return {
            'enabled': user.is_otp_enabled(),
            'confirmed': user.otp_device.confirmed if user.otp_device else False,
            'backup_codes_count': user.get_backup_codes_count(),
            'device_name': user.otp_device.name if user.otp_device else None
        }