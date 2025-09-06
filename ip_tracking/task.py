from celery import shared_task
from django.db import models
from django.utils.timezone import now, timedelta
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ["/admin", "/login"]

@shared_task
def detect_anomalies():
    one_hour_ago = now() - timedelta(hours=1)

    # Find IPs exceeding 100 requests/hour
    ip_counts = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(count=models.Count("id"))
    )

    for entry in ip_counts:
        if entry["count"] > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=entry["ip_address"],
                reason="Excessive requests (>100 in 1 hour)"
            )

    # Find IPs accessing sensitive paths
    sensitive_logs = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=SENSITIVE_PATHS
    ).values("ip_address", "path")

    for log in sensitive_logs:
        SuspiciousIP.objects.get_or_create(
            ip_address=log["ip_address"],
            reason=f"Accessed sensitive path: {log['path']}"
        )
