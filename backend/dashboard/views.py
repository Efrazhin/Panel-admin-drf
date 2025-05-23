from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated 
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import get_authorization_header



class DashboardDataAPIView(APIView):
    def get(self, request):
        jwt_authenticator = JWTAuthentication()

        # Leer manualmente el token de cookie
        access_token = request.COOKIES.get("access_token")

        if not access_token:
            return Response({"detail": "No autorizado"}, status=401)

        validated = jwt_authenticator.get_validated_token(access_token)
        user = jwt_authenticator.get_user(validated)

        return Response({"message": "Acceso correcto", "user": user.email})

class DashboardUserInfoAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "username": user.username,
            "email": user.email,
            "is_staff": user.is_staff,
        })
