from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.contrib.admin.models import ADDITION, CHANGE, DELETION
from django.contrib.contenttypes.models import ContentType
from django.contrib.admin.models import LogEntry
from django.utils import timezone
from threading import local
# Note To make this work, you need to attach the request.user to the model
#  instance before saving. One common pattern is overriding
# perform_create / perform_update in your DRF views and setting:
# serializer.save(_current_user=self.request.user)


# Thread local storage for storing current user
_thread_locals = local()


def get_current_user():
    """Get the current user from thread local storage"""
    return getattr(_thread_locals, 'user', None)


def set_current_user(user):
    """Set the current user in thread local storage"""
    _thread_locals.user = user


@receiver(pre_save)
def set_audit_fields(sender, instance, **kwargs):
    """
    Automatically set created_by and updated_by fields for models using AuditMixin
    """
    # Check if the model has audit fields
    has_created_by = hasattr(instance, 'created_by')
    has_updated_by = hasattr(instance, 'updated_by')

    if not (has_created_by or has_updated_by):
        return

    # Get current user from thread local storage
    current_user = get_current_user()

    # For new instances, set created_by
    if has_created_by and instance._state.adding and current_user and current_user.is_authenticated:
        instance.created_by = current_user

    # For all saves, set updated_by
    if has_updated_by and current_user and current_user.is_authenticated:
        instance.updated_by = current_user


@receiver(post_save)
def log_save(sender, instance, created, **kwargs):
    if sender._meta.app_label in ["auth", "admin"]:  # skip system models
        return
    user = getattr(instance, "_current_user", None)
    if user:
        LogEntry.objects.log_action(
            user_id=user.pk,
            content_type_id=ContentType.objects.get_for_model(instance).pk,
            object_id=instance.pk,
            object_repr=str(instance),
            action_flag=ADDITION if created else CHANGE,
            change_message="Saved via API",
        )

@receiver(post_delete)
def log_delete(sender, instance, **kwargs):
    user = getattr(instance, "_current_user", None)
    if user:
        LogEntry.objects.log_action(
            user_id=user.pk,
            content_type_id=ContentType.objects.get_for_model(instance).pk,
            object_id=instance.pk,
            object_repr=str(instance),
            action_flag=DELETION,
            change_message="Deleted via API",
        )