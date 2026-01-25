# portal/middleware_sessions.py
from django.utils import timezone
from portal.utils.security import get_client_ip

class SessionActivityMiddleware:
    """
    Store lightweight per-session metadata:
    - last_seen (timestamp)
    - ip
    - ua (user agent)
    Updates at most once per 60 seconds to reduce DB writes.
    """
    UPDATE_EVERY_SECONDS = 60

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        try:
            if request.user.is_authenticated and hasattr(request, "session"):
                now = timezone.now()
                last = request.session.get("last_seen")

                should_update = True
                if last:
                    # last can be stored as ISO string
                    try:
                        last_dt = timezone.datetime.fromisoformat(last)
                        if timezone.is_naive(last_dt):
                            last_dt = timezone.make_aware(last_dt, timezone.get_current_timezone())
                        delta = (now - last_dt).total_seconds()
                        should_update = delta >= self.UPDATE_EVERY_SECONDS
                    except Exception:
                        should_update = True

                if should_update:
                    request.session["last_seen"] = now.isoformat()
                    request.session["ip"] = get_client_ip(request) or ""
                    request.session["ua"] = (request.META.get("HTTP_USER_AGENT") or "")[:255]
        except Exception:
            # never block requests because of session metadata
            pass

        return response
