"""
Custom authentication URLs with properly tagged views
"""
from django.urls import path, include
from . import auth_views
from .views import HistoryListView

urlpatterns = [
    # Custom authentication endpoints with proper tags
    path('login/', auth_views.LoginView.as_view(), name='rest_login'),
    path('logout/', auth_views.LogoutView.as_view(), name='rest_logout'),
    path('user/', auth_views.UserDetailsView.as_view(), name='rest_user_details'),
    path('password/change/', auth_views.PasswordChangeView.as_view(), name='rest_password_change'),
    path('password/reset/', auth_views.PasswordResetView.as_view(), name='rest_password_reset'),
    path(
        'password/reset/confirm/<uid>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(),
        name='password_reset_confirm',
    ),

    # JWT token endpoints
    path('token/refresh/', auth_views.CustomTokenRefreshView.as_view(), name='token_refresh'),

    # Registration endpoints
    path('registration/', auth_views.RegisterView.as_view(), name='rest_register'),
    path('registration/verify-email/', auth_views.VerifyEmailView.as_view(), name='rest_verify_email'),
    path('registration/resend-email/', auth_views.ResendEmailVerificationView.as_view(), name='rest_resend_email'),

    # Two-Factor Authentication
    path('2fa/setup/', auth_views.TwoFactorSetupView.as_view(), name='2fa-setup'),
    path('2fa/verify-setup/', auth_views.TwoFactorVerifySetupView.as_view(), name='2fa-verify-setup'),
    path('2fa/verify-login/', auth_views.TwoFactorVerifyLoginView.as_view(), name='2fa-verify-login'),
    path('2fa/disable/', auth_views.TwoFactorDisableView.as_view(), name='2fa-disable'),
    path('2fa/regenerate-backup-codes/', auth_views.TwoFactorRegenerateBackupCodesView.as_view(), name='2fa-regenerate-backup-codes'),
    path('2fa/status/', auth_views.TwoFactorStatusView.as_view(), name='2fa-status'),
]

urlpatterns += [
    path('history/', HistoryListView.as_view(), name='history-list'),
]