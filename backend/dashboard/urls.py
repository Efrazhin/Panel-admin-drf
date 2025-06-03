# dashboard/urls.py

from django.urls import path
from .views import *
urlpatterns = [
    # Usuarios
    path('usuarios/', usuarios_list_view, name='usuarios_list_view'),
    path('usuarios/form/', usuarios_create_view, name='usuarios_create_view'),
    path('usuarios/form/<int:usuario_id>/', usuarios_edit_view, name='usuarios_edit_view'),

    # Dashboard
    path('dashboard/', dashboard, name='dashboard'),
    # Permisos
    path('permisos/', permisos_list_view, name='permisos_list_view'),
    path('roles/<int:rol_pk>/permisos/', rol_permisos_form_view, name='rol_permisos_form_view'),
    path('usuarios/<int:user_pk>/permisos/', usuario_permisos_form_view, name='usuario_permisos_form_view'),
    # Roles
    path('roles/', roles_list_view, name='roles_list_view'),
    path('roles/form/', roles_create_view, name='roles_create_view'),
    path('roles/form/<int:rol_id>/', roles_edit_view, name='roles_edit_view'),
    path('roles/delete/<int:rol_id>/', roles_delete_view, name='roles_delete_view'),

    # Otras vistas
    path('exportar-usuarios/', exportar_usuarios, name='exportar_usuarios'),
    path('estadisticas/', estadisticas, name='estadisticas'),
    path('login-page/', login_page, name='login'),
    path('acceso-denegado/', acceso_denegado_view, name='acceso_denegado'),

    # Registro vía formulario HTML
    path('register/', register_form_view, name='register_form'),
]
