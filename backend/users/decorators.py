from rest_framework.response import Response
from rest_framework import status
from functools import wraps

def rol_requerido(roles_permitidos=[]):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(self, request, *args, **kwargs):
            roles_usuario = [r.nombre for r in request.user.get_roles()]
            if not any(rol in roles_permitidos for rol in roles_usuario):
                return Response({'detail': 'Rol no autorizado.'}, status=status.HTTP_403_FORBIDDEN)
            return view_func(self, request, *args, **kwargs)
        return _wrapped_view
    return decorator
