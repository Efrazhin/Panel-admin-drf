from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.apps import apps
from .models import *
from django.db.utils import ProgrammingError

@receiver(post_migrate)
def create_default_roles(sender, **kwargs):
    if sender.name != 'users':  # Cambiá 'users' si tu app se llama diferente
        return

    # Verificamos si ya hay roles creados
    if Rol.objects.exists():
        return  # Ya hay roles en la base de datos, no hacemos nada

    # Creamos los roles iniciales si no existen (solo una vez)
    roles_iniciales = [
        "Administrador",
        "Psicólogo",
        "Secretaria",
        "Empleado"
    ]

    for nombre in roles_iniciales:
        Rol.objects.get_or_create(nombre=nombre)


def crear_permisos_signal(sender, **kwargs):
    """
    Tras cada migrate, asegura que existan estos permisos.
    Para añadir nuevos permisos, edita esta lista y vuelve a migrar.
    """
    Permiso = apps.get_model('users', 'Permiso')
    permiso_definidos = [
        ('listar_usuario',   'Listar Usuario'),
        ('añadir_usuario',   'Añadir Usuario'),
        ('editar_usuario',   'Editar Usuario'),
        ('eliminar_usuario', 'Eliminar Usuario'),
        # ← Aquí añade futuros permisos: ('codename', 'Nombre Legible')
        # ej: ('agregar_objeto', 'Agrear Objeto')
    ]

    try:
        existentes = set(Permiso.objects.values_list('codename', flat=True))
        for codename, nombre in permiso_definidos:
            if codename not in existentes:
                Permiso.objects.create(codename=codename, nombre=nombre)
    except ProgrammingError:
        # Si la tabla aún no existe (primer migrate), ignora
        pass
