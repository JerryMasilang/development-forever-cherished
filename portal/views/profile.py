from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.urls import reverse

from portal.forms.__init__ import EmailChangeForm


@login_required
def profile(request):
    active_tab = request.GET.get("tab", "general")
    email_form = EmailChangeForm(user=request.user)

    if request.method == "POST":
        action = request.POST.get("action", "")

        if action == "change_email":
            email_form = EmailChangeForm(request.POST, user=request.user)
            if email_form.is_valid():
                messages.success(
                    request, "Verification link sent to your new email address."
                )
                return redirect(f"{reverse('portal:profile')}?tab=security")

            active_tab = "security"
            messages.error(request, "Please correct the error below.")

    return render(
        request,
        "portal/profile.html",
        {"active_tab": active_tab, "email_form": email_form},
    )
