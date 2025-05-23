from rest_framework import generics, permissions
from .serializers import RegisterSerializer, ChangePasswordSerializer, UserSerializer, LoginSerializer
from .models import CustomUser
from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse


# Renderiza el formulario HTML
def login_page(request):
    return render(request, 'login.html')

# Procesa el login y setea tokens en cookies
@api_view(['POST'])
def login_api(request):
    email = request.data.get('email')
    password = request.data.get('password')

    user = authenticate(request, username=email, password=password)

    if user is not None:
        refresh = RefreshToken.for_user(user)
        response = JsonResponse({'message': 'Login exitoso'})

        response.set_cookie(
            key='access_token',
            value=str(refresh.access_token),
            httponly=True,
            secure=False,
            samesite='Lax'
        )
        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            httponly=True,
            secure=False,
            samesite='Lax'
        )
        return response
    else:
        return Response({'non_field_errors': 'Correo o contraseña incorrectos.'}, status=401)


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer  # Ajusta según tu serializer

    def get_queryset(self):
        return CustomUser.objects.all()


class UserDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = [IsAuthenticated]

    def get_object(self, queryset=None):
        return self.request.user

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            if not user.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Contraseña actual incorrecta"]}, status=400)

            user.set_password(serializer.data.get("new_password"))
            user.save()
            return Response({"detail": "Contraseña actualizada correctamente"})

        return Response(serializer.errors, status=400)
