from rest_framework import generics, permissions
from .serializers import *
from .models import *
from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
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
        access_token = str(refresh.access_token)

        response = JsonResponse({'message': 'Login exitoso'})
        response.set_cookie(
            key='access_token',
            value=access_token,
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


@api_view(['POST'])
def logout_view(request):
    response = JsonResponse({'message': 'Sesión cerrada correctamente'})
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    return response


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mis_permisos(request):
    user = request.user
    roles = UsuarioRol.objects.filter(usuario=user).select_related('rol')
    permisos = set()
    for ur in roles:
        permisos.update(ur.rol.permisos.values_list('nombre', flat=True))

    return Response({
        "usuario": user.username,
        "permisos": list(permisos)
    })


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer  

    def get_queryset(self):
        return CustomUser.objects.all()


class UserDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


