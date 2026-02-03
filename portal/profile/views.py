from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages

from portal.models import UserProfile
from .services import regenerate_recovery_codes

from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from portal.models import MFARecoveryCode


@login_required
def profile_settings(request):
    profile = getattr(request.user, "profile", None)

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()

        # Regenerate recovery codes
        if action == "recovery_codes":
            regenerate_recovery_codes(request, request.user)
            return redirect("portal:profile")

    return render(
        request,
        "portal/profile/settings.html",
        {
            "profile": profile,
        },
    )


# @login_required
# def profile_recovery_codes(request):
#     codes = (
#         request.user.mfarecoverycode_set
#         .filter(is_used=False)
#         .order_by("created_at")
#     )
#     return render(
#         request,
#         "portal/profile/recovery_codes.html",
#         {"codes": codes},
#     )
@login_required
def profile_recovery_codes(request):
    # Do NOT rely on request.user.<reverse_manager> because related_name may differ
    codes = (
        MFARecoveryCode.objects
        .filter(user=request.user, used_at__isnull=True)
        .order_by("id")
    )
    return render(request, "portal/profile/recovery_codes.html", {"codes": codes})


@login_required
def profile_stepup_verify(request):
    return render(
        request,
        "portal/profile/stepup_verify.html"
    )


# @login_required
# @stepup_required
# def profile_stepup_verify(request):
#     return render(
#         request,
#         "portal/profile/stepup_verify.html"
#     )


@login_required
def profile_email_change(request):
    return render(
        request,
        "portal/profile/email_change.html"
    )


@login_required
def profile_email_change_error(request):
    return render(
        request,
        "portal/profile/email_change_error.html"
    )
