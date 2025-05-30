def permisos(request):
    """
    Inyecta en el contexto de TODAS las plantillas:
        PERMISOS = lista de codenames de request.user
    """
    if request.user.is_authenticated:
        return {'PERMISOS': request.user.get_permisos()}
    return {'PERMISOS': []}
