import functools
from django.shortcuts import redirect
from django.http import HttpResponseForbidden
from .utils import usuario_tiene_permiso
from .authentication import JWTFromCookieAuthentication

def permiso_y_roles(
    perm_codename: str,
    roles: list[str] = None,
    login_url: str = '/dashboard/login-page/',
    forbidden_url: str | None = '/dashboard/acceso-denegado/'
):
    """
    Decorador para vistas que devuelven HTML. Verifica:
      - Si no está autenticado: redirige a login_url.
      - Si tiene el permiso `perm_codename`: deja pasar.
      - O si su rol está en roles_requeridos: deja pasar.
      - Si no, redirige o devuelve 403.
    """
    roles = roles or []

    def decorator(view_func):
        @functools.wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Verificar autenticación usando JWTFromCookieAuthentication
            jwt_auth = JWTFromCookieAuthentication()
            auth_result = jwt_auth.authenticate(request)
            
            if auth_result is None:
                return redirect(login_url)
                
            user, token = auth_result
            request.user = user

            # 1) Si tiene el permiso explícito
            if usuario_tiene_permiso(user, perm_codename):
                return view_func(request, *args, **kwargs)

            # 2) Si su rol está en roles
            if user.rol and user.rol.nombre in roles:
                return view_func(request, *args, **kwargs)

            # 3) Denegado
            if forbidden_url:
                return redirect(forbidden_url)
            return HttpResponseForbidden("No tienes permiso para acceder a esta sección.")
        return _wrapped_view
    return decorator
