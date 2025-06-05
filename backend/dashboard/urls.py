# backend/dashboard/urls.py

from django.urls import path
from .views import *

urlpatterns = [
    # Login / Registro
    path('login-page/', login_page, name='login'),
    path('register/', register_form_view, name='register_form'),
    path('acceso-denegado/', acceso_denegado_view, name='acceso_denegado'),

    # Dashboard principal (puedes usar base.html o una vista específica)
    path('dashboard/', dashboard, name='dashboard'),

    # Usuarios
    path('usuarios/', usuarios_list_view, name='usuarios_list_view'),
    path('usuarios/form/', usuarios_create_view, name='usuarios_create_view'),
    path('usuarios/form/<int:usuario_id>/', usuarios_edit_view, name='usuarios_edit_view'),
    path('usuarios/<int:user_pk>/permisos/', usuario_permisos_list_view, name='usuario_permisos_list_view'),
    path('usuario/permisos/', usuario_permisos_list_view, name='usuario_permisos_list_view'),

    # Roles
    path('roles/', roles_list_view, name='roles_list_view'),
    path('roles/form/', roles_create_view, name='roles_create_view'),
    path('roles/form/<int:rol_id>/', roles_edit_view, name='roles_edit_view'),
    path('roles/delete/<int:rol_id>/', roles_delete_view, name='roles_delete_view'),
    path('roles/<int:rol_pk>/ver-permisos/', roles_permisos_list_view, name='roles_permisos_list_view'),
    path('roles/<int:rol_pk>/permisos/', rol_permisos_form_view, name='rol_permisos_form_view'),

    # Permisos generales
    path('permisos/', permisos_list_view, name='permisos_list_view'),
]
