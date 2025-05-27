from functools import wraps
from rest_framework.response import Response
from rest_framework import status
from .models import UsuarioRol

def require_permission(nombre_permiso):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            user = request.user
            if not user.is_authenticated:
                return Response({'error': 'No autenticado'}, status=401)

            roles = UsuarioRol.objects.filter(usuario=user).select_related('rol')
            for ur in roles:
                if ur.rol.permisos.filter(nombre=nombre_permiso).exists():
                    return view_func(request, *args, **kwargs)

            return Response({'error': 'No tiene permiso'}, status=403)

        return _wrapped_view
    return decorator
