"""
Management command to initialize the accounts app with basic roles and permissions.
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from django.db import IntegrityError
from datetime import timedelta
from apps.accounts.models import UserRole, UserProfile
from apps.accounts.constants import ROLE_DEFINITIONS
from faker import Faker
import random
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Initialize the accounts app with roles, permissions, and sample data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--sample-users',
            type=int,
            default=5,
            help='Number of sample users to create (default: 5)'
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing data before initializing'
        )
        parser.add_argument(
            '--skip-sample-data',
            action='store_true',
            help='Skip creating sample users, only create roles/permissions'
        )

    def handle(self, *args, **options):
        sample_users = options['sample_users']
        clear_data = options['clear']
        skip_sample_data = options['skip_sample_data']

        self.stdout.write(self.style.NOTICE('Initializing accounts app...'))

        if clear_data:
            self.stdout.write('Clearing existing data...')
            self._clear_existing_data()

        # Step 1: Create custom permissions
        self._create_custom_permissions()

        # Step 2: Create default roles
        self._create_default_roles()

        # Step 3: Update role permissions
        self._update_role_permissions()

        # Step 4: Create default admin user
        self._create_admin_user()

        if not skip_sample_data:
            # Step 5: Create sample data
            self._create_sample_data(sample_users)

        self.stdout.write(self.style.SUCCESS('Accounts app initialization completed!'))

    def _clear_existing_data(self):
        """Clear all existing accounts data"""
        try:
            UserProfile.objects.all().delete()
            User.objects.all().delete()
            UserRole.objects.all().delete()
            self.stdout.write('Cleared existing accounts data')
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'Error clearing data: {e}'))

    def _create_custom_permissions(self):
        """Create basic custom permissions"""
        self.stdout.write('Creating custom permissions...')

        # Get content types for accounts models
        user_ct = ContentType.objects.get_for_model(User)
        user_role_ct = ContentType.objects.get_for_model(UserRole)

        # Define basic permissions
        custom_permissions = [
            # User permissions
            (user_ct, 'view_dashboard', 'Can view dashboard'),
            (user_ct, 'can_assign_roles', 'Can assign roles to users'),
            (user_ct, 'can_view_all_users', 'Can view all users in the system'),
            (user_ct, 'can_manage_permissions', 'Can manage permissions'),
            (user_ct, 'can_manage_roles', 'Can manage roles'),
            (user_ct, 'manage_users', 'Can manage users'),

            # Role permissions
            (user_role_ct, 'manage_roles', 'Can manage user roles'),
        ]

        # Create permissions if they don't exist
        created_count = 0
        for content_type, codename, name in custom_permissions:
            permission, created = Permission.objects.get_or_create(
                codename=codename,
                content_type=content_type,
                defaults={'name': name}
            )

            if created:
                created_count += 1
                self.stdout.write(f'  Created permission: {content_type.app_label}.{codename}')

        self.stdout.write(self.style.SUCCESS(f'Created {created_count} custom permissions'))

    def _create_default_roles(self):
        """Create default roles"""
        self.stdout.write('Creating default roles...')

        created_count = 0
        for role_name, role_data in ROLE_DEFINITIONS.items():
            role, created = UserRole.objects.get_or_create(
                name=role_name,
                defaults={
                    'display_name': role_data.get('display_name', role_name.title()),
                    'description': role_data['description'],
                    'is_active': True
                }
            )

            if created:
                created_count += 1
                self.stdout.write(f'  Created role: {role_name}')

        self.stdout.write(self.style.SUCCESS(f'Created {created_count} roles'))

    def _update_role_permissions(self):
        """Update role permissions"""
        self.stdout.write('Updating role permissions...')

        for role_name, role_data in ROLE_DEFINITIONS.items():
            try:
                role = UserRole.objects.get(name=role_name)
                permissions = []

                # Get permissions for this role
                for perm_codename in role_data.get('permissions', []):
                    try:
                        permission = Permission.objects.get(codename=perm_codename)
                        permissions.append(permission)
                    except Permission.DoesNotExist:
                        self.stdout.write(self.style.WARNING(f'  Permission {perm_codename} not found'))

                # Update role permissions
                role.permissions.set(permissions)
                self.stdout.write(f'  Updated permissions for role: {role_name}')

            except UserRole.DoesNotExist:
                self.stdout.write(self.style.WARNING(f'  Role {role_name} not found'))

        self.stdout.write(self.style.SUCCESS('Role permissions updated'))

    def _create_admin_user(self):
        """Create default admin user"""
        self.stdout.write('Creating admin user...')

        try:
            admin_role = UserRole.objects.get(name='admin')
        except UserRole.DoesNotExist:
            self.stdout.write(self.style.WARNING('Admin role not found, skipping admin user creation'))
            return

        # Check if admin user already exists
        if User.objects.filter(email='admin@example.com').exists():
            self.stdout.write('Admin user already exists')
            return

        # Create admin user
        admin_user = User.objects.create_user(
            username='admin',
            email='admin@gmail.com',
            password='user@12345',
            first_name='Admin',
            last_name='User',
            is_staff=True,
            is_superuser=True,
            is_approved=True,
            is_verified=True
        )
        admin_user.role = admin_role
        admin_user.save()

        # Update admin profile (created by signal)
        admin_user.profile.bio = 'System Administrator'
        admin_user.profile.preferred_language = 'en'
        admin_user.profile.save()

        self.stdout.write(self.style.SUCCESS('Created admin user: admin@example.com'))

    def _create_sample_data(self, sample_users):
        """Create sample users and data"""
        self.stdout.write(f'Creating {sample_users} sample users...')

        fake = Faker()
        roles = list(UserRole.objects.filter(is_active=True))

        if not roles:
            self.stdout.write(self.style.WARNING('No active roles found, skipping sample data creation'))
            return

        created_count = 0
        for i in range(sample_users):
            # Create sample user
            first_name = fake.first_name()
            last_name = fake.last_name()
            username = fake.user_name()
            email = f'{first_name.lower()}.{last_name.lower()}@gmail.com'

            try:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password='user@12345!',
                    first_name=first_name,
                    last_name=last_name,
                    is_approved=True,
                    is_verified=random.choice([True, False])
                )

                # Assign random role
                user.role = random.choice(roles)
                user.save()

                # Update user profile (created by signal)
                user.profile.bio = fake.text(max_nb_chars=200)
                user.profile.preferred_language = random.choice(['en', 'es', 'fr'])
                user.profile.allow_notifications = random.choice([True, False])
                user.profile.save()

                created_count += 1

            except IntegrityError:
                # Skip if user already exists
                continue

        self.stdout.write(self.style.SUCCESS(f'Created {created_count} sample users'))