from functools import wraps
from django.http import HttpResponseForbidden
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse_lazy
from functools import wraps

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


def roles_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            role = getattr(getattr(request.user, "profile", None), "role", None)
            if role not in allowed_roles:
                messages.error(request, "You are not authorized to access that page.")
                return redirect(reverse_lazy("portal:dashboard:dashboard"))
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator