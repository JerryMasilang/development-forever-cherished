# portal/views.py
from __future__ import annotations

from io import BytesIO

import qrcode
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from .models import MFARecoveryCode
from .decorators import admin_required
from django_otp.plugins.otp_totp.models import TOTPDevice
from .decorators import admin_required
from portal.utils.security import audit
from .forms import EmailChangeForm
from .forms import (
    DistributorApplicationForm,
    PortalAuthenticationForm,
    UserCreateForm,
    UserEditForm,
)
from .models import DistributorApplication  # keep if used elsewhere
from portal.utils.security import get_notifications_for_user




# -------------------------
# Auth
# -------------------------


# -------------------------
# Users (admin-required)
# -------------------------
User = get_user_model()



