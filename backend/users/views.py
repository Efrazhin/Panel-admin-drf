# users/views.py

from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import FormParser, MultiPartParser, JSONParser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

from .models import Rol, Usuario
from .serializers import (
    RolSerializer,
    UsuarioSerializer,
    PermissionSerializer,
    RolPermisosUpdateSerializer,
    UsuarioPermisosUpdateSerializer,
    RegisterSerializer
)
from .utils import usuario_tiene_permiso
from .decorators import permiso_y_roles

# ——————————————
#   CRUD de Roles
# ——————————————

class RolViewSet(viewsets.ModelViewSet):
    """
    CRUD de Rol. Cada acción mapea a un permiso automático:
      list/retrieve  → view_rol
      create         → add_rol
      update/partial → change_rol
      destroy        → delete_rol
    """
    queryset = Rol.objects.all()
    serializer_class = RolSerializer
    permission_classes = [IsAuthenticated]

    def initial(self, request, *args, **kwargs):
        # Primero llamamos al inicializador base para que DRF asigne self.action, entre otras cosas
        super().initial(request, *args, **kwargs)

        # Mapeo acción → codename de permiso
        action_perm_map = {
            'list': 'view_rol',
            'retrieve': 'view_rol',
            'create': 'add_rol',
            'update': 'change_rol',
            'partial_update': 'change_rol',
            'destroy': 'delete_rol',
        }
        perm = action_perm_map.get(self.action)

        if perm:
            user = request.user
            # Si no tiene el permiso ni es Administrador, bloqueamos
            if not usuario_tiene_permiso(user, perm) and not (user.rol and user.rol.nombre == 'Administrador'):
                return Response({'detail': 'No tienes permiso para esta acción.'}, status=status.HTTP_403_FORBIDDEN)


class UsuarioViewSet(viewsets.ModelViewSet):
    """
    CRUD de Usuario. Cada acción mapea a un permiso automático:
      list/retrieve  → view_user
      create         → add_user
      update/partial → change_user
      destroy        → delete_user
    """
    queryset = Usuario.objects.all()
    serializer_class = UsuarioSerializer
    permission_classes = [IsAuthenticated]

    def initial(self, request, *args, **kwargs):
        # Llamamos al inicializador base primero
        super().initial(request, *args, **kwargs)

        # Mapeo acción → codename de permiso
        action_perm_map = {
            'list': 'view_user',
            'retrieve': 'view_user',
            'create': 'add_user',
            'update': 'change_user',
            'partial_update': 'change_user',
            'destroy': 'delete_user',
        }
        perm = action_perm_map.get(self.action)

        if perm:
            user = request.user
            if not usuario_tiene_permiso(user, perm) and not (user.rol and user.rol.nombre == 'Administrador'):
                return Response({'detail': 'No tienes permiso para esta acción.'}, status=status.HTTP_403_FORBIDDEN)


# ——————————————
#   Registro de Usuario (API)
# ——————————————

@api_view(['POST'])
@permission_classes([AllowAny])
@parser_classes([FormParser, MultiPartParser, JSONParser])
def register_view(request):
    """
    POST /users/api/register/
    Crea un nuevo Usuario a partir de datos de formulario o JSON.
    Body JSON o form-data:
      {
        "username": "...",
        "email": "...",
        "password": "...",
        "password2": "...",
        "rol": "NombreDelRol"
      }
    """
    serializer = RegisterSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    user = serializer.save()
    return Response(serializer.data, status=status.HTTP_201_CREATED)


# ——————————————
#   Login / Logout
# ——————————————

@api_view(['POST'])
@permission_classes([AllowAny])
@parser_classes([FormParser, MultiPartParser, JSONParser])
def login_view(request):
    """
    POST /users/api/login/
    Puede recibir JSON o form-data: { "email": "...", "password": "..." }.
    Genera JWT (access y refresh) y los guarda en cookies HttpOnly.
    Responde con datos básicos del usuario.
    """
    email = request.data.get('email')
    password = request.data.get('password')

    user = Usuario.objects.filter(email=email).first()
    if not user or not user.check_password(password):
        return Response({'detail': 'Credenciales inválidas.'}, status=status.HTTP_401_UNAUTHORIZED)

    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)

    response = Response({
        'detail': 'Login exitoso.',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'rol': user.rol.nombre if user.rol else None
        }
    }, status=status.HTTP_200_OK)

    # Establecer cookies (en desarrollo secure=False; en producción secure=True)
    response.set_cookie(
        key='access_token',
        value=access_token,
        httponly=True,
        secure=False,
        samesite='Lax',
        max_age=3600
    )
    response.set_cookie(
        key='refresh_token',
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite='Lax',
        max_age=86400
    )

    return response


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """
    POST /users/api/logout/
    Borra las cookies de acceso y refresh.
    """
    response = Response({'detail': 'Logout exitoso.'}, status=status.HTTP_200_OK)
    response.delete_cookie('access_token', path='/')
    response.delete_cookie('refresh_token', path='/')
    return response


# ——————————————
#   Listar Permisos (API)
# ——————————————

class PermisosListAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if not usuario_tiene_permiso(user, 'view_permission') and not (user.rol and user.rol.nombre == 'Administrador'):
            return Response({'detail': 'No autorizado.'}, status=status.HTTP_403_FORBIDDEN)

        permisos = Permission.objects.all()
        serializer = PermissionSerializer(permisos, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# ——————————————
#   Actualizar Permisos de Rol (API)
# ——————————————

class RolPermisosUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, rol_pk):
        user = request.user
        if not usuario_tiene_permiso(user, 'change_rol') and not (user.rol and user.rol.nombre == 'Administrador'):
            return Response({'detail': 'No autorizado.'}, status=status.HTTP_403_FORBIDDEN)

        rol = get_object_or_404(Rol, pk=rol_pk)
        serializer = RolPermisosUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        permisos_ids = serializer.validated_data['permisos_ids']
        rol.permisos.clear()
        for pid in permisos_ids:
            try:
                p = Permission.objects.get(pk=pid)
                rol.permisos.add(p)
            except Permission.DoesNotExist:
                continue

        rol.save()
        return Response({'detail': 'Permisos del rol actualizados.'}, status=status.HTTP_200_OK)


# ——————————————
#   Actualizar Permisos Adicionales de Usuario (API)
# ——————————————

class UsuarioPermisosUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, user_pk):
        user_req = request.user
        if not usuario_tiene_permiso(user_req, 'change_user') and not (user_req.rol and user_req.rol.nombre == 'Administrador'):
            return Response({'detail': 'No autorizado.'}, status=status.HTTP_403_FORBIDDEN)

        usuario = get_object_or_404(Usuario, pk=user_pk)
        serializer = UsuarioPermisosUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        permisos_ids = serializer.validated_data['permisos_ids']
        usuario.permisos_adicionales.clear()
        for pid in permisos_ids:
            try:
                p = Permission.objects.get(pk=pid)
                usuario.permisos_adicionales.add(p)
            except Permission.DoesNotExist:
                continue

        usuario.save()
        return Response({'detail': 'Permisos adicionales del usuario actualizados.'}, status=status.HTTP_200_OK)


# ——————————————
#   Crear Permiso Dinámico (API)
# ——————————————

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def crear_permiso_custom(request):
    user = request.user
    if not usuario_tiene_permiso(user, 'add_permission') and not (user.rol and user.rol.nombre == 'Administrador'):
        return Response({'detail': 'No autorizado para crear permisos.'}, status=status.HTTP_403_FORBIDDEN)

    codename = request.data.get('codename')
    nombre_humano = request.data.get('name')
    modelo = request.data.get('modelo')

    if not codename or not nombre_humano or not modelo:
        return Response({'detail': 'Debes enviar "codename", "name" y "modelo".'}, status=status.HTTP_400_BAD_REQUEST)

    if modelo == 'usuario':
        ct = ContentType.objects.get_for_model(Usuario)
    elif modelo == 'rol':
        ct = ContentType.objects.get_for_model(Rol)
    else:
        return Response({'detail': 'Modelo no reconocido.'}, status=status.HTTP_400_BAD_REQUEST)

    existe = Permission.objects.filter(content_type=ct, codename=codename).exists()
    if existe:
        return Response({'detail': 'Ese permiso ya existe.'}, status=status.HTTP_400_BAD_REQUEST)

    perm = Permission.objects.create(
        codename=codename,
        name=nombre_humano,
        content_type=ct
    )
    return Response({
        'detail': 'Permiso creado correctamente.',
        'permiso': {
            'id': perm.id,
            'codename': perm.codename,
            'name': perm.name,
            'content_type': perm.content_type.id
        }
    }, status=status.HTTP_201_CREATED)


# ——————————————
#   Exportar Usuarios a CSV (API)
# ——————————————

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def usuarios_exportar_csv(request):
    if not usuario_tiene_permiso(request.user, 'export_user'):
        return Response({'detail': 'No autorizado.'}, status=status.HTTP_403_FORBIDDEN)

    import csv
    from django.http import HttpResponse

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="usuarios.csv"'

    writer = csv.writer(response)
    writer.writerow(['ID', 'Username', 'Email'])
    for u in Usuario.objects.all():
        writer.writerow([u.id, u.username, u.email])

    return response


# ——————————————
#   Estadísticas (API)
# ——————————————

class EstadisticasAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not usuario_tiene_permiso(request.user, 'view_stats'):
            return Response({'detail': 'No autorizado.'}, status=status.HTTP_403_FORBIDDEN)

        from django.db.models import Count
        datos = Usuario.objects.values('rol__nombre').annotate(total=Count('id'))
        return Response(datos, status=status.HTTP_200_OK)
