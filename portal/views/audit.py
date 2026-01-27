# User = get_user_model()
from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import render
from portal.decorators.roles import roles_required
from portal.models import AuditLog




@login_required
@roles_required("Administrator", "Manager")
def audit_log_view(request):
    qs = AuditLog.objects.select_related("actor", "target_user").all()

    # Filters
    q = (request.GET.get("q") or "").strip()
    action = (request.GET.get("action") or "").strip()
    actor = (request.GET.get("actor") or "").strip()
    target = (request.GET.get("target") or "").strip()
    date_from = (request.GET.get("from") or "").strip()
    date_to = (request.GET.get("to") or "").strip()

    if q:
        qs = qs.filter(
            Q(action__icontains=q)
            | Q(reason__icontains=q)
            | Q(ip__icontains=q)
            | Q(actor__email__icontains=q)
            | Q(target_user__email__icontains=q)
        )

    if action:
        qs = qs.filter(action=action)

    if actor:
        qs = qs.filter(actor__email__icontains=actor)

    if target:
        qs = qs.filter(target_user__email__icontains=target)

    if date_from:
        qs = qs.filter(created_at__date__gte=date_from)

    if date_to:
        qs = qs.filter(created_at__date__lte=date_to)

    # Pagination
    paginator = Paginator(qs, 25)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    # For action dropdown
    action_choices = (
        AuditLog.objects.values_list("action", flat=True).distinct().order_by("action")
    )

    return render(
        request,
        "portal/audit/audit_list.html",
        {
            "page_obj": page_obj,
            "action_choices": action_choices,
            "filters": {
                "q": q,
                "action": action,
                "actor": actor,
                "target": target,
                "from": date_from,
                "to": date_to,
            },
        },
    )
