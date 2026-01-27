from portal.utils.security import get_notifications_for_user


def navbar_notifications(request):
    if not request.user.is_authenticated:
        return {"notifications": [], "notification_count": 0}

    items = get_notifications_for_user(request.user)
    return {"notifications": items, "notification_count": len(items)}
