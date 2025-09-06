from django.http import JsonResponse
from ratelimit.decorators import ratelimit
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
@ratelimit(key="ip", rate="5/m", method=["POST"], block=True)   # Anonymous
@ratelimit(key="ip", rate="10/m", method=["POST"], block=True)  # Authenticated
def login_view(request):
    if request.method == "POST":
        # Example logic (replace with your real auth flow)
        username = request.POST.get("username")
        password = request.POST.get("password")
        if username == "admin" and password == "password":
            return JsonResponse({"message": "Login successful"})
        return JsonResponse({"error": "Invalid credentials"}, status=401)

    return JsonResponse({"error": "POST required"}, status=405)
