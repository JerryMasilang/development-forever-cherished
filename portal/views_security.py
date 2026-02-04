# portal/views_security.py
"""
Security Shim (Phase 4.5)

This module is intentionally thin.
It re-exports security views that now live inside feature modules.
"""

from __future__ import annotations

# MFA recovery (security implementation)
from portal.mfa.views_security import mfa_recovery

# Profile security (settings, step-up, email change, recovery codes generation)
from portal.profile.views_security import (
    profile_settings,
    stepup_verify,
    recovery_codes_generate,
    request_email_change,
    confirm_email_change,
    email_change_verify,
    email_change_confirm,
)

# Auth security (rate-limited password reset)
from portal.auth.views_security import RateLimitedPasswordResetView
