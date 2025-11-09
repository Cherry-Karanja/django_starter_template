"""
Management command to initialize all apps in the project.
This command orchestrates the initialization of all Django apps by calling their respective setup/initialize commands.
"""
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Initialize all apps in the project with their default data and configurations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--apps',
            nargs='*',
            help='Specific apps to initialize (default: all available apps)'
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing data before initializing'
        )
        parser.add_argument(
            '--skip-sample-data',
            action='store_true',
            help='Skip creating sample data, only create essential configurations'
        )
        parser.add_argument(
            '--sample-users',
            type=int,
            default=5,
            help='Number of sample users to create (default: 5)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force initialization even if apps are already initialized'
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('🚀 Starting unified app initialization...')
        )

        # Define the initialization commands for each app
        app_commands = {
            'accounts': {
                'command': 'initialize_accounts',
                'description': 'Initialize user roles, permissions, and sample users',
                'options': {
                    'sample_users': options['sample_users'],
                    'clear': options['clear'],
                    'skip_sample_data': options['skip_sample_data']
                }
            },
            'notifications': {
                'command': 'setup_notifications',
                'description': 'Set up notification templates and events',
                'options': {
                    'clear': options.get('clear', False)
                }
            },
            'security': {
                'command': 'setup_security',
                'description': 'Configure security settings and policies',
                'options': {}
            }
        }

        # Filter apps if specified
        if options['apps']:
            specified_apps = set(options['apps'])
            app_commands = {
                app: config for app, config in app_commands.items()
                if app in specified_apps
            }

        if not app_commands:
            self.stdout.write(
                self.style.WARNING('No valid apps specified for initialization.')
            )
            return

        self.stdout.write(f'Found {len(app_commands)} apps to initialize:')
        for app_name, config in app_commands.items():
            self.stdout.write(f'  • {app_name}: {config["description"]}')

        # Execute initialization commands in dependency order
        execution_order = ['accounts', 'security', 'notifications']  # Define dependency order
        ordered_apps = [app for app in execution_order if app in app_commands]

        self.stdout.write(f'\n📋 Initialization order: {" → ".join(ordered_apps)}')

        successful_apps = []
        failed_apps = []

        for app_name in ordered_apps:
            config = app_commands[app_name]
            self.stdout.write(f'\n{self.style.SUCCESS("⚙️")} Initializing {app_name}...')

            try:
                # Call the specific command for this app
                command_options = config['options'].copy()
                call_command(config['command'], **command_options)

                successful_apps.append(app_name)
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Successfully initialized {app_name}')
                )

            except Exception as e:
                error_msg = str(e)
                self.stdout.write(
                    self.style.ERROR(f'❌ Failed to initialize {app_name}: {error_msg}')
                )
                failed_apps.append((app_name, error_msg))
                logger.error(f'Failed to initialize {app_name}: {error_msg}')

        # Summary
        self.stdout.write('\n' + '='*70)
        self.stdout.write(self.style.SUCCESS('📊 INITIALIZATION SUMMARY'))
        self.stdout.write('='*70)

        if successful_apps:
            self.stdout.write(f'{self.style.SUCCESS("✅")} Successfully initialized {len(successful_apps)} apps:')
            for app in successful_apps:
                self.stdout.write(f'   • {app}')

        if failed_apps:
            self.stdout.write(f'{self.style.ERROR("❌")} Failed to initialize {len(failed_apps)} apps:')
            for app, error in failed_apps:
                self.stdout.write(f'   • {app}: {error}')

        # Final status
        if successful_apps and not failed_apps:
            self.stdout.write(
                self.style.SUCCESS('\n🎉 All apps initialized successfully!')
            )
            self.stdout.write('\n💡 Next steps:')
            self.stdout.write('   • Run migrations: python manage.py migrate')
            self.stdout.write('   • Create superuser: python manage.py createsuperuser')
            self.stdout.write('   • Start server: python manage.py runserver')

        elif successful_apps:
            self.stdout.write(
                self.style.WARNING(f'\n⚠️ Partially successful: {len(successful_apps)}/{len(successful_apps) + len(failed_apps)} apps initialized')
            )
            self.stdout.write('Check the errors above and try re-running with --force if needed.')
        else:
            self.stdout.write(
                self.style.ERROR('\n💥 No apps were initialized successfully')
            )
            self.stdout.write('Check your configuration and try again.')

        self.stdout.write('='*70)