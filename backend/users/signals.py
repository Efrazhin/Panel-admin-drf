from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from .models import Rol, Usuario

@receiver(post_migrate)
def crear_o_actualizar_rol_administrador(sender, **kwargs):
    """
    Cada vez que corre una migración, asegurarse de que exista el rol Administrador
    y de que tenga asignados TODOS los permisos actuales de la base de datos.
    """
    # 1) Obtener o crear el rol "Administrador"
    rol_admin, creado = Rol.objects.get_or_create(nombre="Administrador")

    # 2) Obtener todos los permisos (tanto automáticos de Django como los definidos manualmente)
    todos_permisos = Permission.objects.all()

    # 3) Asignar el set completo de permisos al rol "Administrador"
    rol_admin.permisos.set(todos_permisos)
    rol_admin.save()

    # 4) Verificar existencia de un superusuario (solo uno basta)
    if not Usuario.objects.filter(is_superuser=True).exists():
        # Crear el superusuario inicial
        Usuario.objects.create_superuser(
            username="admin",
            email="admin@tudominio.com",
            password="ContrasenaSegura123!"
        )
        # Asignar rol Administrador al superusuario recién creado
        admin_user = Usuario.objects.get(email="admin@tudominio.com")
        admin_user.rol = rol_admin
        admin_user.save()

    
@receiver(post_migrate)
def actualizar_nombres_permisos(sender, **kwargs):
    ct_usr = ContentType.objects.get_for_model(Usuario)
    for codename, verbose in Usuario._meta.permissions:
        perm_obj, created = Permission.objects.get_or_create(
            codename=codename,
            content_type=ct_usr,
            defaults={'name': verbose}
        )
        if not created and perm_obj.name != verbose:
            perm_obj.name = verbose
            perm_obj.save()

    ct_rol = ContentType.objects.get_for_model(Rol)
    for codename, verbose in Rol._meta.permissions:
        perm_obj, created = Permission.objects.get_or_create(
            codename=codename,
            content_type=ct_rol,
            defaults={'name': verbose}
        )
        if not created and perm_obj.name != verbose:
            perm_obj.name = verbose
            perm_obj.save()
