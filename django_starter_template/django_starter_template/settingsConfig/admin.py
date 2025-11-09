"""
Django Admin Interface Configuration for the Application
=========================================================

This module contains Django Jazzmin admin interface configurations including:
- Admin site branding and appearance
- Navigation menu configuration
- Custom links and icons
- UI tweaks and customization
"""

from decouple import config

# Get site name from environment variable with fallback
SITE_NAME = config('SITENAME', default='Django')

# Django Jazzmin Configuration
JAZZMIN_SETTINGS = {
    # title of the window (Will default to current_admin_site.site_title if absent or None)
    "site_title": f"{SITE_NAME} Admin",

    # Title on the login screen (19 chars max) (defaults to current_admin_site.site_header if absent or None)
    "site_header": SITE_NAME,

    # Title on the brand (19 chars max) (defaults to current_admin_site.site_header if absent or None)
    "site_brand": SITE_NAME,

    # Logo to use for your site, must be present in static files, used for brand on top left
    "site_logo": None,  # Can be set to a logo file path later

    # Logo to use for your site, must be present in static files, used for login form logo
    "login_logo": None,

    # Logo to use for light theme
    "site_logo_light": None,

    # CSS classes that are applied to the logo above
    "site_logo_classes": "img-circle",

    # Relative path to a favicon for your site, will default to site_logo if absent (ideally 32x32 px)
    "site_icon": None,

    # Welcome text on the login screen
    "welcome_sign": f"Welcome to {SITE_NAME} Admin",

    # Copyright on the footer
    "copyright": f"{SITE_NAME} Team",

    # List of model admins to search from the search bar, search bar omitted if excluded
    "search_model": ["accounts.User"],

    # Field name on user model that contains avatar ImageField/URLField/Charfield or a callable that receives the user
    "user_avatar": None,

    ############
    # Top Menu #
    ############

    # Links to put along the top menu
    "topmenu_links": [
        # Url that gets reversed (Permissions can be added)
        {"name": "Home", "url": "admin:index", "permissions": ["auth.view_user"]},

        # external url that opens in a new window (Permissions can be added)
        {"name": "API Docs (Swagger)", "url": "/api/v1/docs/", "new_window": True},
        {"name": "API Docs (ReDoc)", "url": "/api/v1/redoc/", "new_window": True},

        # model admin to link to (Permissions checked against model)
        {"model": "accounts.User"},

        # App with dropdown menu to all its models pages (Permissions checked against models)
        {"app": "accounts"},
    ],

    #############
    # User Menu #
    #############

    # Additional links to include in the user menu on the top right ("app" url type is not allowed)
    "usermenu_links": [
        {"name": "API Docs (Swagger)", "url": "/api/v1/docs/", "new_window": True},
        {"name": "API Docs (ReDoc)", "url": "/api/v1/redoc/", "new_window": True},
        {"model": "accounts.User"}
    ],

    #############
    # Side Menu #
    #############

    # Whether to display the side menu
    "show_sidebar": True,

    # Whether to auto expand the menu
    "navigation_expanded": True,

    # Hide these apps when generating side menu e.g (auth)
    "hide_apps": [],

    # Hide these models when generating side menu (e.g auth.user)
    "hide_models": [],

    # List of apps (and/or models) to base side menu ordering off of (does not need to contain all apps/models)
    "order_with_respect_to": ["accounts", "core", "auth"],

    # Custom links to append to app groups, keyed on app name
    "custom_links": {
        # "accounts": [{
        #     "name": "User Analytics",
        #     "url": "accounts_admin:user_analytics",
        #     "icon": "fas fa-chart-bar",
        #     "permissions": ["accounts.view_user"]
        # }]
    },

    # Custom icons for side menu apps/models See https://fontawesome.com/icons?d=gallery&m=free&v=5.0.0,5.0.1,5.0.10,5.0.11,5.0.12,5.0.13,5.0.2,5.0.3,5.0.4,5.0.5,5.0.6,5.0.7,5.0.8,5.0.9,5.1.0,5.1.1,5.2.0,5.3.0,5.3.1,5.4.0,5.4.1,5.4.2,5.13.0,5.12.0,5.11.0,5.10.0,5.9.0,5.8.2,5.8.1,5.7.2,5.7.1,5.7.0,5.6.3,5.6.1,5.6.0,5.5.0,5.4.2
    # for the full list of 5.13.0 free icon classes
    "icons": {
        "auth": "fas fa-users-cog",
        "auth.user": "fas fa-user",
        "auth.Group": "fas fa-users",
        "accounts.User": "fas fa-user-circle",
        "core": "fas fa-cogs",
        "sites.Site": "fas fa-globe",
        "account.EmailAddress": "fas fa-envelope",
        "socialaccount.SocialAccount": "fas fa-share-alt",
        "socialaccount.SocialApplication": "fas fa-mobile-alt",
        "authtoken.Token": "fas fa-key",
        "authtoken.TokenProxy": "fas fa-key",
        "token_blacklist.BlacklistedToken": "fas fa-ban",
        "token_blacklist.OutstandingToken": "fas fa-clock",
    },
    # Icons that are used when one is not manually specified
    "default_icon_parents": "fas fa-chevron-circle-right",
    "default_icon_children": "fas fa-circle",

    #################
    # Related Modal #
    #################
    # Use modals instead of popups
    "related_modal_active": False,

    #############
    # UI Tweaks #
    #############
    # Relative paths to custom CSS/JS scripts (must be present in static files)
    "custom_css": None,
    "custom_js": None,
    # Whether to link font from fonts.googleapis.com (use custom_css to supply font otherwise)
    "use_google_fonts_cdn": True,
    # Whether to show the UI customizer on the sidebar
    "show_ui_builder": True,

    ###############
    # Change view #
    ###############
    # Render out the change view as a single form, or in tabs, current options are
    # - single
    # - horizontal_tabs (default)
    # - vertical_tabs
    # - collapsible
    # - carousel
    "changeform_format": "horizontal_tabs",
    # override change forms on a per modeladmin basis
    "changeform_format_overrides": {"accounts.User": "collapsible", "auth.Group": "vertical_tabs"},
    # Add a language dropdown into the admin
    "language_chooser": False,
}

JAZZMIN_UI_TWEAKS = {
    "navbar_small_text": False,
    "footer_small_text": False,
    "body_small_text": False,
    "brand_small_text": False,
    "brand_colour": False,
    "accent": "accent-primary",
    "navbar": "navbar-white navbar-light",
    "no_navbar_border": False,
    "navbar_fixed": False,
    "layout_boxed": False,
    "footer_fixed": False,
    "sidebar_fixed": False,
    "sidebar": "sidebar-dark-primary",
    "sidebar_nav_small_text": False,
    "sidebar_disable_expand": False,
    "sidebar_nav_child_indent": False,
    "sidebar_nav_compact_style": False,
    "sidebar_nav_legacy_style": False,
    "sidebar_nav_flat_style": False,
    "theme": "default",
    "dark_mode_theme": None,
    "button_classes": {
        "primary": "btn-outline-primary",
        "secondary": "btn-outline-secondary",
        "info": "btn-info",
        "warning": "btn-warning",
        "danger": "btn-danger",
        "success": "btn-success"
    }
}