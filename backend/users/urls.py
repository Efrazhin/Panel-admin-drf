
# users/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import *
router = DefaultRouter()
router.register(r'roles', RolViewSet, basename='rol')
router.register(r'usuarios', UsuarioViewSet, basename='usuario')

urlpatterns = [
    # CRUD de roles y usuarios
    path('api/', include(router.urls)),

    # Autenticación
    path('api/login/', login_view, name='login'),
    path('api/logout/', logout_view, name='logout'),
    path('api/register/', register_view, name='register'),
    path('api/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Crear permisos custom
    path('api/crear-permiso/', crear_permiso_custom, name='crear_permiso_custom'),

    # Listar permisos
    path('api/permisos/', PermisosListAPIView.as_view(), name='permisos_list'),

    # Actualizar permisos de rol
    path('api/roles/<int:rol_pk>/permisos/', RolPermisosUpdateAPIView.as_view(), name='roles_update_permisos'),

    # Eliminar un permiso específico del rol
    path('api/roles/<int:rol_pk>/permisos/<int:perm_pk>/', RolPermisoDeleteAPIView.as_view(), name='roles_delete_permiso'),

    # Actualizar permisos adicionales de usuario
    path('api/usuarios/<int:user_pk>/permisos/', UsuarioPermisosUpdateAPIView.as_view(), name='usuarios_update_permisos'),

    # Exportar usuarios a CSV
    path('api/usuarios/exportar/', usuarios_exportar_csv, name='usuarios_exportar_csv'),

    # Estadísticas
    path('api/estadisticas/', EstadisticasAPIView.as_view(), name='estadisticas_api'),
]

