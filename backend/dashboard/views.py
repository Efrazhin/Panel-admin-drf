# dashboard/views.py

from django.shortcuts import render, HttpResponseRedirect
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import get_object_or_404
from users.decorators import permiso_y_roles
from users.utils import usuario_tiene_permiso
from users.models import Rol, Usuario
from users.views import register_view
from users.authentication import JWTFromCookieAuthentication


def login_page(request):
    """
    Págaina de login HTML. El formulario envía POST a /users/api/login/.
    """
    return render(request, 'login_page.html')

    
def chequear_autenticacion(request):
    """
    Extrae y valida el JWT desde la cookie 'access_token'.
    Si no existe o es inválido, redirige a login-page.
    """
    jwt_authenticator = JWTFromCookieAuthentication()
    
    try:
        # Usar authenticate directamente
        auth_result = jwt_authenticator.authenticate(request)
        if auth_result is None:
            print("No se pudo autenticar")  # Para debugging
            return HttpResponseRedirect('/dashboard/login-page/')
            
        user, token = auth_result
        request.user = user
        return None

    except Exception as e:
        print(f"Error de autenticación: {e}")  # Para debugging
        return HttpResponseRedirect('/dashboard/login-page/')


# ---------------- Roles ----------------

@permiso_y_roles('view_rol', roles=['Administrador'])
def roles_list_view(request):
    """
    Lista todos los roles en HTML.
    El JS dentro de roles_list.html hará fetch('/users/api/roles/') para obtener datos.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir
    return render(request, 'roles_list.html')


@permiso_y_roles('add_rol', roles=['Administrador'])
def roles_create_view(request):
    """
    Muestra el formulario para crear un nuevo rol.
    El JS en roles_form.html enviará POST a /users/api/roles/.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir
    context = {'rol_id': None}
    return render(request, 'roles_form.html', context)


@permiso_y_roles('change_rol', roles=['Administrador'])
def roles_edit_view(request, rol_id):
    """
    Muestra el formulario para editar un rol existente.
    El JS en roles_form.html enviará PUT a /users/api/roles/<rol_id>/.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir
    context = {'rol_id': rol_id}
    return render(request, 'roles_form.html', context)


# ---------------- Usuarios ----------------

@permiso_y_roles('view_usuario', roles=['Administrador'])
def usuarios_list_view(request):
    """
    Lista todos los usuarios en HTML.
    El JS dentro de usuarios_list.html hará fetch('/users/api/usuarios/') para obtener datos.
    """
    return render(request, 'usuarios_list.html')


@permiso_y_roles('add_user', roles=['Administrador'])
def usuarios_create_view(request):
    """
    Muestra el formulario para crear un nuevo usuario.
    El JS en usuarios_form.html enviará POST a /users/api/usuarios/.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir

    roles = Rol.objects.all()
    context = {
        'usuario_id': None,
        'roles': roles
    }
    return render(request, 'usuarios_form.html', context)


@permiso_y_roles('change_user', roles=['Administrador'])
def usuarios_edit_view(request, usuario_id):
    """
    Muestra el formulario para editar un usuario existente.
    El JS en usuarios_form.html enviará PUT a /users/api/usuarios/<usuario_id>/.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir

    roles = Rol.objects.all()
    context = {
        'usuario_id': usuario_id,
        'roles': roles
    }
    return render(request, 'usuarios_form.html', context)


# ---------------- Otras vistas protegidas ----------------
@permiso_y_roles('view_permission', roles=['Administrador'])
def permisos_list_view(request):
    redir = chequear_autenticacion(request)
    if redir:
        return redir
    return render(request, 'permisos.html')


@permiso_y_roles('export_user', roles=['Administrador'], login_url='/dashboard/login-page/', forbidden_url='/dashboard/acceso-denegado/')
def exportar_usuarios(request):
    """
    Vista protegida que solo pueden ver quienes tengan permiso 'export_user' o rol 'Administrador'.
    Renderiza exportar_usuarios.html, donde el JS hará fetch('/users/api/usuarios/exportar/').
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir
    return render(request, 'exportar_usuarios.html')


@permiso_y_roles('view_stats', roles=['Administrador'], login_url='/dashboard/login-page/', forbidden_url='/dashboard/acceso-denegado/')
def estadisticas(request):
    """
    Vista protegida que solo pueden ver quienes tengan permiso 'view_stats' o rol 'Administrador'.
    Renderiza estadisticas.html, donde el JS hará fetch('/users/api/estadisticas/').
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir
    return render(request, 'estadisticas.html')



def dashboard(request):
    redir = chequear_autenticacion(request)
    if redir:
        return redir
    return render(request, 'base.html')


def acceso_denegado_view(request):
    """
    Página simple de 'Acceso Denegado'.
    """
    return render(request, 'acceso_denegado.html')


def register_form_view(request):
    """
    Vista que muestra el formulario de registro HTML.
    No requiere autenticación ya que es para nuevos usuarios.
    """
    roles = Rol.objects.all()
    context = {
        'roles': roles,
        'errores': None
    }

    if request.method == 'GET':
        return render(request, 'register_form.html', context)

    # Si es POST, reenviamos los datos al endpoint /users/api/register/
    request._full_data = request.POST  # hack interno para que DRF lea request.POST como data
    request._request = request._request  # conservar la request de Django
    response = register_view(request)
    if response.status_code == 201:
        # Registro exitoso; redirigir a login
        return HttpResponseRedirect('/dashboard/login-page/')
    else:
        # Si hay errores, response.data será un dict con mensajes de error
        context['errores'] = response.data
        return render(request, 'register_form.html', context)


@permiso_y_roles('change_rol', roles=['Administrador'])
def rol_permisos_form_view(request, rol_pk):
    """
    Muestra el formulario HTML para asignar permisos a un rol.
    El JS hará fetch a /users/api/permisos/ para listar todos los permisos,
    y fetch a /users/api/roles/<rol_pk>/ para conocer los permisos actuales.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir

    rol = get_object_or_404(Rol, pk=rol_pk)
    context = {
        'rol_id': rol.id,
        'rol_nombre': rol.nombre
    }
    return render(request, 'permisos_rol_form.html', context)

@permiso_y_roles('change_user', roles=['Administrador'])
def usuario_permisos_form_view(request, user_pk):
    """
    Muestra el formulario HTML para asignar permisos adicionales a un usuario.
    El JS hará fetch a /users/api/permisos/ para listar todos los permisos,
    y fetch a /users/api/usuarios/<user_pk>/ para extraer permisos_adicionales actuales.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir

    usuario = get_object_or_404(Usuario, pk=user_pk)
    context = {
        'usuario_id': usuario.id,
        'usuario_email': usuario.email
    }
    return render(request, 'permisos_usuario_form.html', context)