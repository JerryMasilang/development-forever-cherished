LoginView
from .forms import DistributorApplicationForm,PortalAuthenticationForm,
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render


User = get_user_model()

class PortalLoginView(LoginView):
    template_name = "portal/login.html"
    authentication_form = PortalAuthenticationForm
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

