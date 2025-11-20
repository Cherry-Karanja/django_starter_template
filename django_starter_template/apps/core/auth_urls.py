"""
Custom authentication URLs with properly tagged views
"""
from django.urls import path, include
from dj_rest_auth.views import TokenRefreshView
from drf_spectacular.utils import extend_schema
from . import auth_views
from .serializers import CustomTokenRefreshSerializer
from .views import HistoryListView


# Create a custom TokenRefreshView with proper tags
class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer

    @extend_schema(
        tags=['Authentication'],
        summary="Refresh JWT token",
        description="Refresh JWT access token using refresh token from httpOnly cookies. No request body required.",
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


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
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),

    # Registration endpoints
    path('registration/', auth_views.RegisterView.as_view(), name='rest_register'),
    path('registration/verify-email/', auth_views.VerifyEmailView.as_view(), name='rest_verify_email'),
    path('registration/resend-email/', auth_views.ResendEmailVerificationView.as_view(), name='rest_resend_email'),
]

urlpatterns += [
    path('history/', HistoryListView.as_view(), name='history-list'),
]