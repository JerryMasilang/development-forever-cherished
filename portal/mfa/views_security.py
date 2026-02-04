# portal/views_security.py
from __future__ import annotations
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django_otp import login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice
from portal.utils.security import audit
from django.contrib import messages
from django_otp.plugins.otp_totp.models import TOTPDevice
from portal.utils.security import audit, verify_and_consume_recovery_code









@login_required
def mfa_recovery(request):
    if request.method == "POST":
        code = (request.POST.get("code") or "").strip()
        if verify_and_consume_recovery_code(request.user, code):
            device = (
                TOTPDevice.objects.filter(user=request.user, confirmed=True)
                .order_by("-id")
                .first()
            )
            if device:
                otp_login(request, device)

            audit(request, "MFA_RECOVERY_CODE_USED", target_user=request.user)
            messages.success(request, "Recovery code accepted.")
            return redirect("portal:dashboard:dashboard")

        messages.error(request, "Invalid or already-used recovery code.")
        return redirect("portal:mfa:mfa_recovery")

    return render(request, "portal/mfa_recovery.html")
