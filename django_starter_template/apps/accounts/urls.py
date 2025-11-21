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

    # User Statistics
    path('statistics/', views.UserStatisticsView.as_view(), name='user-stats'),
]