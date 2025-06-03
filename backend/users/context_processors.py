# users/context_processors.py

from .utils import usuario_tiene_permiso
from django.contrib.auth.models import Permission

def user_permissions(request):
    """
    Inyecta en el contexto la lista de codenames de todos los permisos
    que el usuario tiene (tanto por rol como adicionales).
    """
    user = getattr(request, 'user', None)
    if not user or not user.is_authenticated:
        return {'user_perms': []}

    # 1) Obtener permisos desde el rol
    perms_desde_rol = []
    if user.rol:
        perms_desde_rol = list(user.rol.permisos.values_list('codename', flat=True))

    # 2) Obtener permisos adicionales directos del usuario
    perms_adicionales = list(user.permisos_adicionales.values_list('codename', flat=True))

    # Unión de ambos (usamos set solo para eliminar duplicados, luego volvemos a lista)
    todas_permisiones = list(set(perms_desde_rol + perms_adicionales))

    return {'user_perms': todas_permisiones}

