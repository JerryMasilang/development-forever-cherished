from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy

from django.contrib import messages
from django.shortcuts import redirect, render

from portal.forms import DistributorApplicationForm



from portal.forms import (
    PortalAuthenticationForm,
    PortalPasswordResetForm,
)


class PortalLoginView(auth_views.LoginView):
    template_name = "portal/login.html"
    authentication_form = PortalAuthenticationForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        # new login session must re-verify MFA
        self.request.session.pop("portal_mfa_verified", None)
        return super().form_valid(form)



class PortalLogoutView(auth_views.LogoutView):
    next_page = reverse_lazy("portal:login")


class PortalPasswordResetView(auth_views.PasswordResetView):
    template_name = "portal/auth/password_reset.html"
    email_template_name = "portal/auth/password_reset_email.html"
    subject_template_name = "portal/auth/password_reset_subject.txt"
    success_url = reverse_lazy("portal:password_reset_done")
    form_class = PortalPasswordResetForm


class PortalPasswordResetDoneView(auth_views.PasswordResetDoneView):
    template_name = "portal/auth/password_reset_done.html"


class PortalPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = "portal/auth/password_reset_confirm.html"
    success_url = reverse_lazy("portal:password_reset_complete")


class PortalPasswordResetCompleteView(auth_views.PasswordResetCompleteView):
    template_name = "portal/auth/password_reset_complete.html"




# -------------------------
# Distributor application
# -------------------------
def distributor_apply(request):
    if request.method == "POST":
        form = DistributorApplicationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Application submitted. We will contact you once reviewed.")
            return redirect("portal:login")
    else:
        form = DistributorApplicationForm()

    return render(request, "portal/auth/distributor_apply.html", {"form": form})

