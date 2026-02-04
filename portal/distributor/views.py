# portal/distributor/views.py
from __future__ import annotations

from django.shortcuts import render, redirect
from django.contrib import messages

# Import your existing form/model exactly as you already use them
from portal.forms import DistributorApplicationForm  # or move later
from portal.models import DistributorApplication      # if used

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

