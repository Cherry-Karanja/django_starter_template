"""
URLs for the accounts app
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'accounts'

# Create a router for ViewSets
router = DefaultRouter()
router.register(r'users', views.UserViewSet, basename='user')
router.register(r'user-profiles', views.UserProfileViewSet, basename='user-profile')
router.register(r'user-roles', views.UserRoleViewSet, basename='user-role')
router.register(r'user-role-histories', views.UserRoleHistoryViewSet, basename='user-role-history')
router.register(r'user-sessions', views.UserSessionViewSet, basename='user-session')
router.register(r'login-attempts', views.LoginAttemptViewSet, basename='login-attempt')
router.register(r'permissions', views.PermissionViewSet, basename='permission')

urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),

    # Authentication endpoints
    path('auth/register/', views.CustomRegisterView.as_view(), name='custom-register'),
    path('auth/login/', views.CustomLoginView.as_view(), name='custom-login'),

    # User Statistics
    path('statistics/', views.UserStatisticsView.as_view(), name='user-stats'),

    # Two-Factor Authentication
    path('2fa/setup/', views.TwoFactorSetupView.as_view(), name='2fa-setup'),
    path('2fa/verify-setup/', views.TwoFactorVerifySetupView.as_view(), name='2fa-verify-setup'),
    path('2fa/verify-login/', views.TwoFactorVerifyLoginView.as_view(), name='2fa-verify-login'),
    path('2fa/disable/', views.TwoFactorDisableView.as_view(), name='2fa-disable'),
    path('2fa/regenerate-backup-codes/', views.TwoFactorRegenerateBackupCodesView.as_view(), name='2fa-regenerate-backup-codes'),
    path('2fa/status/', views.TwoFactorStatusView.as_view(), name='2fa-status'),
]