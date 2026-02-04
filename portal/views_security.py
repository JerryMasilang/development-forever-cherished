# portal/views_security.py
"""
Security Shim (Phase 4.5)

This module is intentionally thin.
It re-exports security views that now live inside feature modules.
"""
from __future__ import annotations

from portal.profile.views_security import (
    profile_settings,
    stepup_verify,
    recovery_codes_generate,
    email_change_verify,
    email_change_confirm,
)

from portal.mfa.views_security import mfa_recovery
from portal.auth.views_security import RateLimitedPasswordResetView
