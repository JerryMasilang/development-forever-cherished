from django import template
from portal.utils.security import get_notifications_for_user as _get_notifications

register = template.Library()

@register.simple_tag
def get_notifications_for_user(user):
    if not user or not getattr(user, "is_authenticated", False):
        return []
    return _get_notifications(user)
