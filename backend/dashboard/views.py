from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import HttpResponseRedirect
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated 
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import get_authorization_header
from users.decorators import *
from rest_framework import status, permissions
from users.serializers import *
from users.models import *



def redireccionar_dashboard(request):
    jwt_authenticator = JWTAuthentication()
    token = request.COOKIES.get("access_token")

    if not token:
        return HttpResponseRedirect('/login/')  # Redirigir a login si no hay token

    try:
        validated_token = jwt_authenticator.get_validated_token(token)
        user = jwt_authenticator.get_user(validated_token)
        request.user = user  # asignar usuario para la vista
    except Exception:
        return HttpResponseRedirect('/login/')
    user = request.user
    roles = [r.nombre for r in user.get_roles()]  # suponiendo que tienes `get_roles()`

    if 'Administrador' in roles:
        return redirect('dashboard_admin')
    elif 'Secretaria' in roles:
        return redirect('dashboard_secretaria')
    elif 'Invitado' in roles:
        return redirect('dashboard_invitado')
    else:
        return redirect('acceso_denegado')  # opcional


def dashboard_secretaria(request):
    jwt_authenticator = JWTAuthentication()
    token = request.COOKIES.get("access_token")

    if not token:
        return HttpResponseRedirect('/login/')  # Redirigir a login si no hay token

    try:
        validated_token = jwt_authenticator.get_validated_token(token)
        user = jwt_authenticator.get_user(validated_token)
        request.user = user  # asignar usuario para la vista
    except Exception:
        return HttpResponseRedirect('/login/')
      # Obtener roles del usuario
    roles = [rol.nombre for rol in user.get_roles()]

    # Pasar datos a la plantilla
    context = {
        'usuario': user,
        'roles': roles,
    }
    return render(request, 'secretaria.html', context)






def dashboard_admin(request):
    #-----------------Este bloque autentica si hay token, no se usa mas @loginrequired 
    jwt_authenticator = JWTAuthentication()
    token = request.COOKIES.get("access_token")

    if not token:
        return HttpResponseRedirect('/login/')  # Redirigir a login si no hay token

    try:
        validated_token = jwt_authenticator.get_validated_token(token)
        user = jwt_authenticator.get_user(validated_token)
        request.user = user  # asignar usuario para la vista
    except Exception:
        return HttpResponseRedirect('/login/')
    #-------------------------------------------------------------
    # Obtener roles del usuario
    roles = [rol.nombre for rol in user.get_roles()]

    # Pasar datos a la plantilla
    context = {
        'usuario': user,
        'roles': roles,
    }

    return render(request, 'admin.html', context)

class DashboardAdminAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        roles = [r.nombre for r in user.get_roles()]

        return Response({
            'nombre': user.username,
            'email': user.email,
            'roles': roles,
        })

class TienePermisoPersonalizado:
    def __init__(self, permiso_requerido):
        self.permiso_requerido = permiso_requerido

    def __call__(self, user):
        return self.permiso_requerido in user.get_permisos()



class UsuarioListView(APIView):
    permission_classes = [IsAuthenticated]

    @rol_requerido(roles_permitidos=['Administrador','Secretaria'])
    def get(self, request):
        usuarios = CustomUser.objects.all()
        serializer = UserSerializer(usuarios, many=True)
        return Response(serializer.data)

class UsuarioCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if not TienePermisoPersonalizado('crear_usuario')(request.user):
            return Response({'detail': 'No tiene permiso para crear usuarios.'}, status=status.HTTP_403_FORBIDDEN)

        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




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
