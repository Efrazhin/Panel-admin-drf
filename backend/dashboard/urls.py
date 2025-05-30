from django.urls import path
from .views import *

urlpatterns = [
    path('admin-api/', DashboardAdminAPIView.as_view(), name='admin-api'),
    path('redirect/', redireccionar_dashboard, name='redirect'),
    path('dashboard_admin/', dashboard_admin, name='dashboard_admin'),
    path('dashboard_secre/', dashboard_secretaria, name='dashboard_secre'),
    path('user-info/', DashboardUserInfoAPIView.as_view(), name='dashboard_user_info'),
    path('secretaria/', dashboard_secretaria, name='dashboard_secretaria'),
    path('usuarios/', UsuarioListView.as_view(), name='listar_usuarios'),
    path('usuarios/crear/', UsuarioCreateView.as_view(), name='crear_usuario'),
]
