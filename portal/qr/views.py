# portal/qr/views.py
from __future__ import annotations

# QR module imports live here (legacy views_legacy.py removed)
from io import BytesIO
import qrcode

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404
from django.conf import settings




def _public_base() -> str:
    # Add this in settings.py (see patch below)
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
def qr_control_center(request):
    """
    UI prototype: placeholder QR list + computed URLs + memorial activation controls.
    Database models are not yet implemented, so all values are derived from sample dicts.
    """

    # TEMP role gating (replace with your real role system later)
    user_role = getattr(getattr(request.user, "profile", None), "role", None)
    can_change_status = user_role in ["Administrator", "Manager"]

    qrs = [
        {
            "item_no": "0001",
            "id_code": "FC-5555",
            "status": "AVAILABLE",
            "memorial_of": None,
            "qr_id": "FC-9F2A1C3D",
            "custodian_name": None,
            "custodian_id": None,
            "enrollment_key_masked": "********",
            "assigned_to": None,
            "date_generated": "2026-01-20 15:10",
            "date_registered": None,
            "date_assigned": None,
            "custodian_enabled": True,
            "admin_override_status": "none",
            "admin_locked": False,
        },
        {
            "item_no": "0002",
            "id_code": "FC-5532",
            "status": "RESERVED",
            "memorial_of": None,
            "qr_id": "FC-1A7C8B2E",
            "custodian_name": None,
            "custodian_id": None,
            "enrollment_key_masked": "********",
            "assigned_to": None,
            "date_generated": "2026-01-20 15:10",
            "date_registered": None,
            "date_assigned": None,
            "custodian_enabled": True,
            "admin_override_status": "none",
            "admin_locked": False,
        },
        {
            "item_no": "0003",
            "id_code": "FC-5531",
            "status": "ASSIGNED",
            "memorial_of": None,
            "qr_id": "FC-7D3E2A19",
            "custodian_name": None,
            "custodian_id": None,
            "enrollment_key_masked": "********",
            "assigned_to": "ABC Funeral Services",
            "date_generated": "2026-01-18 10:20",
            "date_registered": None,
            "date_assigned": "2026-01-18 10:25",
            "custodian_enabled": True,
            "admin_override_status": "none",
            "admin_locked": False,
        },
        {
            "item_no": "0004",
            "id_code": "FC-5554",
            "status": "DISTRIBUTED",
            "memorial_of": None,
            "qr_id": "FC-4B8C2D1A",
            "custodian_name": None,
            "custodian_id": None,
            "enrollment_key_masked": "********",
            "assigned_to": "XYZ Lapida Maker",
            "date_generated": "2026-01-16 09:00",
            "date_registered": None,
            "date_assigned": "2026-01-16 09:10",
            "custodian_enabled": True,
            "admin_override_status": "none",
            "admin_locked": False,
        },
        {
            "item_no": "0005",
            "id_code": "FC-5558",
            "status": "REGISTERED",
            "memorial_of": "Fernando Masilang",
            "qr_id": "FC-0C1A9E2B",
            "custodian_name": "Jerry Masilang",
            "custodian_id": "98374",
            "enrollment_key_masked": "********",
            "assigned_to": "XYZ Lapida Maker",
            "date_generated": "2026-01-15 08:00",
            "date_registered": "2026-01-16 12:30",
            "date_assigned": "2026-01-15 08:10",
            "memorial_slug": "fernando-masilang",
            "custodian_enabled": True,
            "admin_override_status": "none",
            "admin_locked": False,
        },
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
        {
            "qrs": qrs,
            "distributors": distributors,
            "can_change_status": can_change_status,
        },
    )


@login_required
def qr_png(request, qr_id: str):
    """
    Returns a PNG QR image encoding the stable redirect link.
    Works in prototype mode (no DB needed).
    """
    qr_url = f"{_public_base()}/q/{qr_id}"
    img = qrcode.make(qr_url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return HttpResponse(buf.getvalue(), content_type="image/png")

