
User = get_user_model()

@login_required
def dashboard(request):
    kpi = {
        "available": 0,
        "reserved": 0,
        "assigned": 0,
        "distributed": 0,
        "registered": 0,
        "total_generated": 0,
    }
    alerts = []
    return render(request, "portal/dashboard.html", {"kpi": kpi, "alerts": alerts})
