from django.contrib import admin
from .models import Rol, Usuario

@admin.register(Rol)
class RolAdmin(admin.ModelAdmin):
    list_display = ('id', 'nombre')
    filter_horizontal = ('permisos',)

@admin.register(Usuario)
class UsuarioAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'username', 'rol', 'is_superuser', 'is_staff')
    list_filter = ('rol', 'is_superuser', 'is_staff')
    search_fields = ('email', 'username')
