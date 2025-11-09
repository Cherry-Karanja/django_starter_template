from apps.accounts.models import UserSession
from django.contrib.sessions.models import Session
from django.utils import timezone
import pytz

discrepancies = []
for us in UserSession.objects.all():
    try:
        ds = Session.objects.get(session_key=us.session_key)
        # Check if Django session is expired
        if timezone.is_naive(ds.expire_date):
            ds_expired = timezone.make_aware(ds.expire_date, pytz.UTC) <= timezone.now()
        else:
            ds_expired = ds.expire_date <= timezone.now()

        # Check if UserSession is expired
        if timezone.is_naive(us.expires_at):
            us_expired = timezone.make_aware(us.expires_at, pytz.UTC) <= timezone.now()
        else:
            us_expired = us.expires_at <= timezone.now()

        if ds_expired != us_expired:
            discrepancies.append((us.id, ds_expired, us_expired))
    except Session.DoesNotExist:
        discrepancies.append((us.id, 'django_session_missing', us.is_expired()))

print(f'Discrepancies found: {len(discrepancies)}')
for d in discrepancies[:5]:  # Show first 5
    print(d)