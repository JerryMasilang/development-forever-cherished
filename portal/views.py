# portal/views.py
"""
Phase 3.3 Shim (NO behavior change)

This file exists only to keep legacy imports working while the real logic
lives in feature modules (dashboard/, mfa/, users/, profile/, auth/, etc.)
"""

from __future__ import annotations




# --- Auth feature (preferred source of truth) ---
from portal.auth.views import (
    PortalLoginView,
    PortalLogoutView,
    PortalPasswordResetView,
    PortalPasswordResetDoneView,
    PortalPasswordResetConfirmView,
    PortalPasswordResetCompleteView,
)

# --- Dashboard feature ---
from portal.dashboard.views import dashboard

# --- MFA feature ---
from portal.mfa.views import (
    mfa_setup,
    mfa_verify,
    mfa_qr_png,
)

# --- Users feature ---
from portal.users.views import (
    user_list,
    user_create,
    user_edit,
    user_reset_mfa,
    user_reset_recovery,
)

# --- Profile feature ---
# Keep this alias because portal/urls.py has legacy "profile/" pointing here
from portal.profile.views import profile_settings

# --- Legacy endpoints not moved yet ---
# (QR + distributor apply, and anything else still living in the old monolith)
from portal.qr.views import (
    qr_control_center,
    qr_png,
)

from portal.auth.views import distributor_apply

