from __future__ import annotations

from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin


class SessionActivityMiddleware(MiddlewareMixin):
    """
    Stores lightweight session metadata for the logged-in user.
    Used by the Profile/Security page to show active sessions.
    """

    def process_request(self, request):
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return None

        # Keep these minimal to avoid cookie bloat.
        request.session["last_seen"] = timezone.now().isoformat()

        # Optional: store IP + UA (useful for session list UX)
        ip = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
        if not ip:
            ip = request.META.get("REMOTE_ADDR", "")

        ua = request.META.get("HTTP_USER_AGENT", "")

        request.session["ip"] = ip
        request.session["ua"] = ua[:255]  # avoid oversized session data

        return None
