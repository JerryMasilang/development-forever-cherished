User = get_user_model()




@login_required
def profile(request):
    """
    Profile page with tabs. Ensures email-change validation errors
    keep the user on the Security tab instead of redirecting to default tab.
    """

    # Default tab from URL (GET)
    active_tab = request.GET.get("tab", "general")

    # Forms (add other forms you already have here)
    email_form = EmailChangeForm(user=request.user)

    # Handle POST actions
    if request.method == "POST":
        action = request.POST.get("action", "")

        # EMAIL CHANGE (Security tab)
        if action == "change_email":
            email_form = EmailChangeForm(request.POST, user=request.user)

            if email_form.is_valid():
                new_email = email_form.cleaned_data["new_email"]

                messages.success(request, "Verification link sent to your new email address.")
                return redirect(f"{reverse('portal:profile')}?tab=security")

            # IMPORTANT: do NOT redirect on error
            # Re-render page and force Security tab active
            active_tab = "security"
            messages.error(request, "Please correct the error below.")

    return render(request, "portal/profile.html", {
        "active_tab": active_tab,
        "email_form": email_form,
        # include other forms your template expects:
        # "password_form": password_form,
        # "mfa_form": mfa_form,
    })