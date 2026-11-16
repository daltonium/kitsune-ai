from django.contrib.auth import authenticate, login, logout
from django.db import IntegrityError, transaction
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from rest_framework.authentication import SessionAuthentication
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from api.errors import api_exception_handler
from .serializers import LoginSerializer, RegisterSerializer


def user_data(user):
    return {
        "id": user.pk,
        "username": user.username,
        "email": user.email,
        "role": user.role,
    }


def auth_error(code, message, status_code):
    return Response(
        {"error": {"code": code, "message": message}},
        status=status_code,
    )


@method_decorator(never_cache, name="dispatch")
@method_decorator(csrf_protect, name="dispatch")
class AuthBaseView(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def get_exception_handler(self):
        return api_exception_handler


class CSRFView(AuthBaseView):
    def get(self, request):
        return Response({"csrf_token": get_token(request)})


class MeView(AuthBaseView):
    def get(self, request):
        if not request.user.is_authenticated:
            return auth_error(
                "not_authenticated",
                "Sign in to continue.",
                401,
            )
        return Response({"user": user_data(request.user)})


class RegisterView(AuthBaseView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_register"

    def post(self, request):
        if request.user.is_authenticated:
            return auth_error(
                "already_authenticated",
                "Sign out before registering another account.",
                409,
            )

        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            with transaction.atomic():
                user = serializer.save()
        except IntegrityError:
            return auth_error(
                "account_conflict",
                "The username or email is already registered.",
                409,
            )

        login(
            request,
            user,
            backend="django.contrib.auth.backends.ModelBackend",
        )
        return Response(
            {
                "user": user_data(user),
                "csrf_token": get_token(request),
            },
            status=201,
        )


class LoginView(AuthBaseView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_login"

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            request=request,
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
        )
        if user is None:
            return auth_error(
                "invalid_credentials",
                "Invalid username or password.",
                401,
            )

        login(request, user)
        return Response({
            "user": user_data(user),
            "csrf_token": get_token(request),
        })


class LogoutView(AuthBaseView):
    def post(self, request):
        logout(request)
        return Response({
            "message": "Signed out.",
            "csrf_token": get_token(request),
        })