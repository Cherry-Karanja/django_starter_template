from rest_framework import serializers
from django.utils import timezone
from typing import Optional
from .models import AuditLog, RateLimit, SecurityEvent, SecuritySettings, APIKey


class AuditLogSerializer(serializers.ModelSerializer):
    user_username = serializers.SerializerMethodField()
    user_email = serializers.CharField(source='user.email', read_only=True)
    ip_address = serializers.CharField(read_only=True)

    def get_user_username(self, obj) -> Optional[str]:
        return obj.user.get_username() if obj.user else None

    class Meta:
        model = AuditLog
        fields = [
            'id', 'user', 'user_username', 'user_email', 'event_type', 'severity',
            'description', 'ip_address', 'user_agent', 'session_key', 'request_path',
            'request_method', 'request_data', 'response_status', 'additional_data',
            'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']


class RateLimitSerializer(serializers.ModelSerializer):
    class Meta:
        model = RateLimit
        fields = [
            'id', 'limit_type', 'identifier', 'endpoint', 'request_count',
            'window_start', 'window_end', 'blocked_until', 'is_blocked'
        ]
        read_only_fields = ['id', 'window_start', 'window_end']


class SecurityEventSerializer(serializers.ModelSerializer):
    user_username = serializers.SerializerMethodField()
    resolved_by_username = serializers.SerializerMethodField()
    related_audit_logs_count = serializers.SerializerMethodField()
    ip_address = serializers.CharField(read_only=True)

    def get_user_username(self, obj) -> Optional[str]:
        return obj.user.get_username() if obj.user else None

    def get_resolved_by_username(self, obj) -> Optional[str]:
        return obj.resolved_by.get_username() if obj.resolved_by else None

    def get_related_audit_logs_count(self, obj) -> int:
        return obj.related_audit_logs.count()

    class Meta:
        model = SecurityEvent
        fields = [
            'id', 'event_type', 'status', 'title', 'description', 'severity',
            'ip_address', 'user', 'user_username', 'related_audit_logs',
            'related_audit_logs_count', 'detection_data', 'resolution_notes',
            'resolved_by', 'resolved_by_username', 'resolved_at',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'related_audit_logs_count']

    def update(self, instance, validated_data):
        # Handle resolution
        if validated_data.get('status') == SecurityEvent.Status.RESOLVED and not instance.resolved_at:
            instance.resolved_by = self.context['request'].user
            instance.resolved_at = serializers.DateTimeField().to_representation(
                instance.resolved_at or timezone.now()
            )
        return super().update(instance, validated_data)


class SecuritySettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecuritySettings
        fields = [
            'id', 'setting_type', 'name', 'description', 'config',
            'is_enabled', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class APIKeySerializer(serializers.ModelSerializer):
    user_username = serializers.SerializerMethodField()
    is_expired = serializers.BooleanField(read_only=True)

    def get_user_username(self, obj) -> Optional[str]:
        return obj.user.get_username() if obj.user else None

    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'key_type', 'key', 'user', 'user_username',
            'permissions', 'rate_limit', 'is_active', 'expires_at',
            'last_used_at', 'is_expired', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'last_used_at', 'is_expired', 'created_at', 'updated_at']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class APIKeyCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating API keys"""

    class Meta:
        model = APIKey
        fields = ['name', 'key_type', 'permissions', 'rate_limit', 'expires_at']
        read_only_fields = ['key']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class SecurityDashboardSerializer(serializers.Serializer):
    """Serializer for security dashboard data"""

    total_audit_logs = serializers.IntegerField()
    critical_events = serializers.IntegerField()
    active_rate_limits = serializers.IntegerField()
    recent_security_events = SecurityEventSerializer(many=True)
    audit_logs_today = serializers.IntegerField()
    blocked_ips = serializers.IntegerField()