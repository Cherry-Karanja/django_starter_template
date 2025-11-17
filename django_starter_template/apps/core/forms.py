from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from accounts.models import User
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import re

class CustomUserCreationForm(UserCreationForm):
    """
    Custom user creation form with additional validation
    """
    email = forms.EmailField(
        required=True,
        help_text="Required. Enter a valid email address."
    )

    class Meta:
        model = User
        fields = ("username", "email", "first_name", "last_name", "password1", "password2")

    def clean_email(self):
        """
        Validate email uniqueness
        """
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError(_("A user with this email already exists."))
        return email

    def clean_username(self):
        """
        Validate username format and uniqueness
        """
        username = self.cleaned_data.get('username')
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            raise ValidationError(_("Username can only contain letters, numbers, and underscores."))
        return username

    def save(self, commit=True):
        """
        Save user with email
        """
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class CustomUserChangeForm(UserChangeForm):
    """
    Custom user change form
    """
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "first_name", "last_name", "is_active", "is_staff", "is_superuser")

    def clean_email(self):
        """
        Validate email uniqueness excluding current user
        """
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise ValidationError(_("A user with this email already exists."))
        return email


class PasswordResetForm(forms.Form):
    """
    Form for password reset request
    """
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'placeholder': 'Enter your email address'})
    )

    def clean_email(self):
        """
        Validate that email exists in the system
        """
        email = self.cleaned_data.get('email')
        if not User.objects.filter(email=email).exists():
            raise ValidationError(_("No account found with this email address."))
        return email


class PasswordResetConfirmForm(forms.Form):
    """
    Form for password reset confirmation
    """
    new_password1 = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(attrs={'placeholder': 'Enter new password'}),
        strip=False,
        help_text="Your password must contain at least 8 characters."
    )
    new_password2 = forms.CharField(
        label="Confirm new password",
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm new password'}),
        strip=False,
        help_text="Enter the same password as before, for verification."
    )

    def clean_new_password2(self):
        """
        Validate password confirmation
        """
        password1 = self.cleaned_data.get("new_password1")
        password2 = self.cleaned_data.get("new_password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError(_("The two password fields didn't match."))
        return password2

    def clean_new_password1(self):
        """
        Validate password strength
        """
        password = self.cleaned_data.get("new_password1")
        if len(password) < 8:
            raise ValidationError(_("Password must be at least 8 characters long."))
        if not re.search(r'[A-Z]', password):
            raise ValidationError(_("Password must contain at least one uppercase letter."))
        if not re.search(r'[a-z]', password):
            raise ValidationError(_("Password must contain at least one lowercase letter."))
        if not re.search(r'\d', password):
            raise ValidationError(_("Password must contain at least one digit."))
        return password


class UserProfileForm(forms.Form):
    """
    Form for updating user profile information
    """
    first_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'First name'})
    )
    last_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'Last name'})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'placeholder': 'Email address'})
    )

    def __init__(self, user=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if user:
            self.fields['first_name'].initial = user.first_name
            self.fields['last_name'].initial = user.last_name
            self.fields['email'].initial = user.email

    def clean_email(self):
        """
        Validate email uniqueness excluding current user
        """
        email = self.cleaned_data.get('email')
        user = getattr(self, 'user', None)
        if user and User.objects.filter(email=email).exclude(pk=user.pk).exists():
            raise ValidationError(_("A user with this email already exists."))
        elif not user and User.objects.filter(email=email).exists():
            raise ValidationError(_("A user with this email already exists."))
        return email


class ChangePasswordForm(forms.Form):
    """
    Form for changing user password
    """
    old_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Current password'}),
        strip=False
    )
    new_password1 = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(attrs={'placeholder': 'New password'}),
        strip=False,
        help_text="Your password must contain at least 8 characters."
    )
    new_password2 = forms.CharField(
        label="Confirm new password",
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm new password'}),
        strip=False,
        help_text="Enter the same password as before, for verification."
    )

    def __init__(self, user=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean_old_password(self):
        """
        Validate old password
        """
        old_password = self.cleaned_data.get("old_password")
        if not self.user.check_password(old_password):
            raise ValidationError(_("Your old password was entered incorrectly. Please enter it again."))
        return old_password

    def clean_new_password2(self):
        """
        Validate password confirmation
        """
        password1 = self.cleaned_data.get("new_password1")
        password2 = self.cleaned_data.get("new_password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError(_("The two password fields didn't match."))
        return password2

    def clean_new_password1(self):
        """
        Validate password strength
        """
        password = self.cleaned_data.get("new_password1")
        if len(password) < 8:
            raise ValidationError(_("Password must be at least 8 characters long."))
        if not re.search(r'[A-Z]', password):
            raise ValidationError(_("Password must contain at least one uppercase letter."))
        if not re.search(r'[a-z]', password):
            raise ValidationError(_("Password must contain at least one lowercase letter."))
        if not re.search(r'\d', password):
            raise ValidationError(_("Password must contain at least one digit."))
        return password