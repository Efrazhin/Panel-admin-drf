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
        return {'user_perms': set()}

    # 1) Obtener permisos desde el rol
    perms_desde_rol = set()
    if user.rol:
        perms_desde_rol = set(user.rol.permisos.values_list('codename', flat=True))

    # 2) Obtener permisos adicionales directos del usuario
    perms_adicionales = set(user.permisos_adicionales.values_list('codename', flat=True))

    # Unión de ambos
    todas_permisiones = perms_desde_rol.union(perms_adicionales)

    # **IMPORTANTE**: devolver un diccionario, no una tupla
    return {'user_perms': todas_permisiones}
