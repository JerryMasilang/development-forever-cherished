from __future__ import annotations

from io import BytesIO

import qrcode
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render


def _public_base() -> str:
    return getattr(settings, "PUBLIC_SITE_BASE_URL", "").rstrip("/")


def _make_public_urls(qr_id: str, status: str, memorial_slug: str | None = None):
    base = _public_base()
    qr_redirect_url = f"{base}/q/{qr_id}"
    enroll_url = f"{base}/enroll/{qr_id}"
    memorial_url = f"{base}/memorial/{memorial_slug}/" if memorial_slug else None

    if status == "REGISTERED" and memorial_url:
        display_url = memorial_url
        display_url_label = "Memorial"
    else:
        display_url = enroll_url
        display_url_label = "Enroll"

    return qr_redirect_url, enroll_url, memorial_url, display_url, display_url_label


def _compute_effective_status(custodian_enabled: bool, admin_override_status: str):
    if admin_override_status == "active":
        return "active"
    if admin_override_status == "inactive":
        return "inactive"
    return "active" if custodian_enabled else "inactive"


@login_required
def qr_png(request, qr_id: str):
    qr_url = f"{_public_base()}/q/{qr_id}"
    img = qrcode.make(qr_url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return HttpResponse(buf.getvalue(), content_type="image/png")


@login_required
def qr_control_center(request):
    user_role = getattr(getattr(request.user, "profile", None), "role", None)
    can_change_status = user_role in ["Administrator", "Manager"]

    qrs = [
        # (keep your sample data list here — unchanged)
    ]

    for row in qrs:
        (
            qr_redirect_url,
            enroll_url,
            memorial_url,
            display_url,
            display_url_label,
        ) = _make_public_urls(row["qr_id"], row["status"], row.get("memorial_slug"))

        row["qr_redirect_url"] = qr_redirect_url
        row["enroll_url"] = enroll_url
        row["memorial_url"] = memorial_url
        row["display_url"] = display_url
        row["display_url_label"] = display_url_label

        row["effective_status"] = _compute_effective_status(
            row.get("custodian_enabled", True),
            row.get("admin_override_status", "none"),
        )

    distributors = ["ABC Funeral Services", "XYZ Lapida Maker", "Guardian Partner"]

    return render(
        request,
        "portal/qr_control_center.html",
        {"qrs": qrs, "distributors": distributors, "can_change_status": can_change_status},
    )
