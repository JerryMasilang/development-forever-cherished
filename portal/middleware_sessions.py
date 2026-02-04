# # portal/middleware_sessions.py
# from __future__ import annotations

# from django.utils import timezone
# from portal.utils.security import get_client_ip

# from portal.models import UserSession


# class SessionActivityMiddleware:
#     """
#     Persist per-session metadata to DB (UserSession) so we can show
#     active sessions and terminate them.

#     Updates at most once per 60 seconds to reduce DB writes.
#     """
#     UPDATE_EVERY_SECONDS = 60

#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         response = self.get_response(request)

#         try:
#             if not getattr(request, "user", None) or not request.user.is_authenticated:
#                 return response
#             if not hasattr(request, "session"):
#                 return response

#             # Ensure session has a key (Django may lazily create)
#             if not request.session.session_key:
#                 request.session.save()

#             session_key = request.session.session_key
#             if not session_key:
#                 return response

#             now = timezone.now()

#             # Throttle using session storage (cheap)
#             last_iso = request.session.get("last_seen")
#             should_update = True
#             if last_iso:
#                 try:
#                     last_dt = timezone.datetime.fromisoformat(last_iso)
#                     if timezone.is_naive(last_dt):
#                         last_dt = timezone.make_aware(last_dt, timezone.get_current_timezone())
#                     should_update = (now - last_dt).total_seconds() >= self.UPDATE_EVERY_SECONDS
#                 except Exception:
#                     should_update = True

#             if not should_update:
#                 return response

#             ip = get_client_ip(request) or ""
#             ua = (request.META.get("HTTP_USER_AGENT") or "")[:255]

#             request.session["last_seen"] = now.isoformat()
#             request.session["ip"] = ip
#             request.session["ua"] = ua

#             # Persist to DB (UserSession)
#             UserSession.objects.update_or_create(
#                 session_key=session_key,
#                 defaults={
#                     "user": request.user,
#                     "ip_address": ip,
#                     "user_agent": ua,
#                     "last_seen_at": now,
#                     "ended_at": None,
#                 },
#             )

#         except Exception as e:
#           import traceback
#           traceback.print_exc()


#         return response

# portal/middleware_sessions.py
from __future__ import annotations

from django.utils import timezone
from portal.utils.security import get_client_ip
from portal.models import UserSession


class SessionActivityMiddleware:
    """
    Persist per-session metadata to DB (UserSession) so we can show
    active sessions and terminate them.

    IMPORTANT: update BEFORE response so the same page render can display it.
    """
    UPDATE_EVERY_SECONDS = 60

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            user = getattr(request, "user", None)
            if user and user.is_authenticated and hasattr(request, "session"):
                # Ensure session key exists
                if not request.session.session_key:
                    request.session.save()

                session_key = request.session.session_key
                if session_key:
                    now = timezone.now()

                    # Throttle using session storage
                    last_iso = request.session.get("last_seen")
                    should_update = True
                    if last_iso:
                        try:
                            last_dt = timezone.datetime.fromisoformat(last_iso)
                            if timezone.is_naive(last_dt):
                                last_dt = timezone.make_aware(
                                    last_dt, timezone.get_current_timezone()
                                )
                            should_update = (now - last_dt).total_seconds() >= self.UPDATE_EVERY_SECONDS
                        except Exception:
                            should_update = True

                    if should_update:
                        ip = get_client_ip(request) or ""
                        ua = (request.META.get("HTTP_USER_AGENT") or "")[:255]

                        # Mark session modified so Django definitely saves it
                        request.session["last_seen"] = now.isoformat()
                        request.session["ip"] = ip
                        request.session["ua"] = ua
                        request.session.modified = True

                        UserSession.objects.update_or_create(
                            session_key=session_key,
                            defaults={
                                "user": user,
                                "ip_address": ip,
                                "user_agent": ua,
                                "last_seen_at": now,
                                "ended_at": None,
                            },
                        )
        except Exception:
            pass

        return self.get_response(request)
