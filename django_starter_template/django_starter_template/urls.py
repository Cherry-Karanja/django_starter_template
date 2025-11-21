"""
URL configuration for django_starter_template project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.shortcuts import redirect
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
from django.conf import settings
from django.conf.urls.static import static
from apps.core import auth_views

urlpatterns = [
    # Root redirect to API documentation
    path('', lambda request: redirect('/api/v1/docs/', permanent=False)),
    
    path('admin/', admin.site.urls),

    # Django allauth URLs for email confirmation and social auth (must be at root level)
    # Override the email confirmation URL to redirect to frontend
    path('accounts/confirm-email/<str:key>/', auth_views.EmailConfirmationRedirectView.as_view(), name='account_confirm_email'),
    path('accounts/', include('allauth.urls')),

    # API v1 endpoints
    path('api/v1/', include([
        path('core/', include('apps.core.urls')),
        path('accounts/', include('apps.accounts.urls')),
        path('security/', include('apps.security.urls')),
        path('notifications/', include('apps.notifications.urls')),
    ])),

        # API Documentation
    path('api/v1/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/v1/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/v1/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    # Add debug toolbar
    import sys
    if 'debug_toolbar' in settings.INSTALLED_APPS and 'test' not in sys.argv:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include('debug_toolbar.urls', namespace='djdt')),
        ] + urlpatterns
    
    # Add browser reload for development
    if 'django_browser_reload' in settings.INSTALLED_APPS and 'test' not in sys.argv:
        urlpatterns = [
            path('__reload__/', include('django_browser_reload.urls')),
        ] + urlpatterns