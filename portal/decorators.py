from functools import wraps
from django.http import HttpResponseForbidden

def admin_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseForbidden("Not authenticated.")
        role = getattr(getattr(request.user, "profile", None), "role", None)
        if request.user.is_superuser or role == "Administrator":
            return view_func(request, *args, **kwargs)
        return HttpResponseForbidden("Admins only.")
    return _wrapped
