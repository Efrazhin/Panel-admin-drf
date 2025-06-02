from django.contrib.auth.models import Permission

def usuario_tiene_permiso(user, perm_codename: str) -> bool:
    """
    Retorna True si user está autenticado y tiene el permiso `perm_codename`,
    ya sea por su rol o por permisos_adicionales.
    """
    if not user.is_authenticated:
        return False

    try:
        permiso = Permission.objects.get(codename=perm_codename)
    except Permission.DoesNotExist:
        return False

    # Si está en permisos del rol
    if user.rol and permiso in user.rol.permisos.all():
        return True

    # Si está en permisos adicionales
    if permiso in user.permisos_adicionales.all():
        return True

    return False
