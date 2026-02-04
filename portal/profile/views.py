# from django.contrib.auth.decorators import login_required
# from django.shortcuts import render, redirect
# from django.contrib import messages

# from portal.models import UserProfile
# from .services import regenerate_recovery_codes

# from django.contrib.auth.decorators import login_required
# from django.shortcuts import render
# from portal.models import MFARecoveryCode

# from django.views.decorators.http import require_POST


from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.views.decorators.http import require_POST

from portal.models import MFARecoveryCode
from .services import regenerate_recovery_codes

@login_required
def profile_settings(request):
    profile = getattr(request.user, "profile", None)

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()

        # Regenerate recovery codes
        if action == "recovery_codes":
            regenerate_recovery_codes(request, request.user)
            return redirect("portal:settings")

    return render(
        request,
        "portal/profile/settings.html",
        {
            "profile": profile,
        },
    )


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



@login_required
@require_POST
def set_theme(request):
    theme = (request.POST.get("theme_preference") or "system").strip()
    if theme not in ("system", "light", "dark"):
        theme = "system"

    prof = request.user.profile
    prof.theme_preference = theme
    prof.save(update_fields=["theme_preference"])

    # Optional: audit log event if you want consistency
    # audit(request, "PREFERENCE_THEME_UPDATED", meta={"theme": theme})

    messages.success(request, "Theme updated.")
    return redirect("portal:settings")  # or wherever your profile settings URL name points