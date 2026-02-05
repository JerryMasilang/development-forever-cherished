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

        profile = getattr(request.user, "profile", None)
        role = getattr(profile, "role", None)
        is_superadmin = bool(getattr(profile, "is_superadmin", False))

        if is_superadmin or role == "Administrator":
            return view_func(request, *args, **kwargs)

        return HttpResponseForbidden("Admins only.")
    return _wrapped


def superadmin_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseForbidden("Not authenticated.")
        profile = getattr(request.user, "profile", None)
        if not getattr(profile, "is_superadmin", False):
            return HttpResponseForbidden("SuperAdmin only.")
        return view_func(request, *args, **kwargs)
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

