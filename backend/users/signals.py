# users/signals.py

from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.contrib.auth.models import Permission
from .models import Rol, Usuario

@receiver(post_migrate)
def crear_rol_administrador(sender, **kwargs):
    """
    Tras las migraciones, asegura:
      1) Que exista un Rol 'Administrador'.
      2) Que exista al menos un superusuario.
    """
    # 1) Crear Rol 'Administrador' si no existe
    if not Rol.objects.filter(nombre="Administrador").exists():
        rol_admin = Rol.objects.create(nombre="Administrador")
        # Asignar todos los permisos automáticos al rol Administrador:
        rol_admin.permisos.set(Permission.objects.all())
        rol_admin.save()

    # 2) Crear superusuario inicial si no existe ninguno
    if not Usuario.objects.filter(is_superuser=True).exists():
        # Utilizamos create_superuser para is_superuser=True e is_staff=True
        Usuario.objects.create_superuser(
            username="admin",
            email="admin@tudominio.com",
            password="ContrasenaSegura123!"
        )
        # Asignar el rol "Administrador" al superusuario
        admin = Usuario.objects.get(email="admin@tudominio.com")
        rol_admin = Rol.objects.get(nombre="Administrador")
        admin.rol = rol_admin
        admin.save()
