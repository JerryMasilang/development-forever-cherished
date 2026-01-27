from django.contrib import messages
from django.contrib.auth.views import LoginView
from django.shortcuts import redirect, render

from portal.forms import DistributorApplicationForm, PortalAuthenticationForm


class PortalLoginView(LoginView):
    template_name = "portal/login.html"
    authentication_form = PortalAuthenticationForm


def distributor_apply(request):
    if request.method == "POST":
        form = DistributorApplicationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(
                request, "Application submitted. We will contact you once reviewed."
            )
            return redirect("portal:login")
    else:
        form = DistributorApplicationForm()

    return render(request, "portal/auth/distributor_apply.html", {"form": form})
