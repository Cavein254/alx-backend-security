from .models import RequestLog, BlockedIP
from django.utils.timezone import now
from django.http import HttpResponseForbidden
from django.core.cache import cache
from ipgeolocation import geolocator

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        ip = self.get_client_ip(request)

        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP has been blocked")
        
        geo_data = cache.get(f"geo:ip")
        if not geo_data:
            try:
                geo_data = geolocator.locate(ip)
            except:
                geo_data = {"country": None, "city": None}
            cache.set(f"geo:{ip}", geo_data, 60 * 60 * 24)

        RequestLog.objects.create(
            ip_address=ip,
            timestamp=now(),
            path=request.path,
            country=geo_data.get("country"),
            city=geo_data.get("city")
        )

        response = self.get_response(request)
        return response
    
    def get_client_ip(self, request):
        """
        Get client IP address, handling proxy headers if present
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip