from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.apps import apps
from .models import Rol, CustomUser

@receiver(post_migrate)
def sync_roles_from_model(sender, **kwargs):
    """
    Tras cada migración, sincroniza la tabla Rol con las opciones
    definidas en CustomUser.ROL_CHOICES.
    """
    # Nos aseguramos de ejecutar solo cuando se migre la app de users
    if sender.name != CustomUser._meta.app_label:
        return

    # Iterar sobre ROL_CHOICES y crear o actualizar cada rol en la BD
    for valor, etiqueta in CustomUser.ROL_CHOICES:
        # Creamos o actualizamos un objeto Rol con nombre == etiqueta
        Rol.objects.update_or_create(
            nombre=etiqueta,
            defaults={},
        )
