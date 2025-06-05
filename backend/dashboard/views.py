# dashboard/views.py

from django.shortcuts import render, HttpResponseRedirect
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import get_object_or_404, redirect
from users.decorators import permiso_y_roles
from users.utils import usuario_tiene_permiso
from users.models import Rol, Usuario, Permission
from users.views import register_view
from users.authentication import JWTFromCookieAuthentication
from django.contrib.auth.models import Permission


def login_page(request):
    """
    Págaina de login HTML. El formulario envía POST a /users/api/login/.
    """
    return render(request, 'login/login_page.html')

    
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

#------------ Roles ----------------
@permiso_y_roles('view_rol', roles=['Administrador'])
def roles_list_view(request):
    """
    Lista todos los roles en HTML.
    El JS dentro de roles_list.html hará fetch('/users/api/roles/') para obtener datos.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir

    # No necesitamos pasar user_perms; el context processor ya inyectó 'user_perms' como lista.
    return render(request, 'rol/roles_list.html', {'roles': Rol.objects.all()})

@permiso_y_roles('add_rol', roles=['Administrador'])
def roles_create_view(request):
    """
    Muestra el formulario para crear un nuevo rol.
    El JS en roles_form.html enviará POST a /users/api/roles/.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir

    # Si quieres usar Django Forms en lugar de JS puro, puedes procesar aquí:
    # Pero en nuestro caso el propio JS hará POST a la API, así que solo renderizamos el template.
    context = {'rol_id': None}
    return render(request, 'rol/roles_form.html', context)

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
    return render(request, 'rol/roles_form.html', context)

@permiso_y_roles('delete_rol', roles=['Administrador'])
def roles_delete_view(request, rol_id):
    """
    Elimina el rol <rol_id> llamando a la API REST (DELETE).
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir

    # El propio JS invoca DELETE; esta vista no se usa para eliminar.
    # Si quisieras un enlace que apunte aquí, podrías hacerlo:
    rol = get_object_or_404(Rol, pk=rol_id)
    rol.delete()
    return redirect('roles_list_view')


@permiso_y_roles('view_rol', roles=['Administrador'])
def roles_permisos_list_view(request, rol_pk):
    """
    Muestra en HTML la lista de permisos que tiene un rol,
    con botones para eliminar cada permiso y un enlace para 'Asignar permisos'.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir

    rol = get_object_or_404(Rol, pk=rol_pk)
    permisos = rol.permisos.all()
    context = {
        'rol': rol,
        'rol_id': rol.id,
        'rol_nombre': rol.nombre,
        'permisos': permisos,
    }
    return render(request, 'rol/roles_permisos_list.html', context)

# ---------------- Usuarios ----------------

@permiso_y_roles('view_usuario', roles=['Administrador'])
def usuarios_list_view(request):
    """
    Lista todos los usuarios en HTML.
    El JS dentro de usuarios_list.html hará fetch('/users/api/usuarios/') para obtener datos.
    """
    return render(request, 'usuarios/usuarios_list.html')


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
    return render(request, 'usuarios/usuarios_form.html', context)


@permiso_y_roles('change_usuario', roles=['Administrador'])
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
    return render(request, 'usuarios/usuarios_form.html', context)

@permiso_y_roles('view_usuario', roles=['Administrador', 'Editor'])
def usuario_permisos_list_view(request, user_pk=None):
    """
    Muestra en HTML la lista de permisos que tiene un usuario.
    Si user_pk es None, muestra los permisos del usuario autenticado.
    Si user_pk es proporcionado y el usuario tiene permiso change_usuario, muestra los permisos de ese usuario.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir

    # Si no se proporciona user_pk, mostrar permisos del usuario actual
    if user_pk is None:
        usuario = request.user
    else:
        # Verificar si el usuario actual tiene permiso para ver otros usuarios
        if not usuario_tiene_permiso(request.user, 'change_usuario') and not (
            request.user.rol and request.user.rol.nombre == 'Administrador'
        ):
            return redirect('acceso_denegado_view')
        usuario = get_object_or_404(Usuario, pk=user_pk)

    context = {
        'usuario': usuario,
        'es_propio': user_pk is None
    }
    return render(request, 'usuarios/usuario_permisos_list.html', context)

# ---------------- Otras vistas protegidas ----------------
@permiso_y_roles('view_permission', roles=['Administrador'])
def permisos_list_view(request):
    """
    Vista que muestra la lista de permisos.
    Solo accesible por el superusuario.
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir
    
    # Verificar si es superusuario
    if not request.user.is_superuser:
        return redirect('acceso_denegado')
        
    return render(request, 'permisos/permisos_list.html')


@permiso_y_roles('export_user', roles=['Administrador'], login_url='/dashboard/login-page/', forbidden_url='/dashboard/acceso-denegado/')
def exportar_usuarios(request):
    """
    Vista protegida que solo pueden ver quienes tengan permiso 'export_user' o rol 'Administrador'.
    Renderiza exportar_usuarios.html, donde el JS hará fetch('/users/api/usuarios/exportar/').
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir
    return render(request, 'usuarios/exportar_usuarios.html')


@permiso_y_roles('view_stats', roles=['Administrador'], login_url='/dashboard/login-page/', forbidden_url='/dashboard/acceso-denegado/')
def estadisticas(request):
    """
    Vista protegida que solo pueden ver quienes tengan permiso 'view_stats' o rol 'Administrador'.
    Renderiza estadisticas.html, donde el JS hará fetch('/users/api/estadisticas/').
    """
    redir = chequear_autenticacion(request)
    if redir:
        return redir
    return render(request, 'frontend/templates/estadisticas/estadisticas.html')



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
        return render(request, 'login/register_form.html', context)

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
        return render(request, 'login/register_form.html', context)


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
    todos_permisos = Permission.objects.all()
    permisos_asignados = rol.permisos.values_list('id', flat=True)
    
    context = {
        'rol_id': rol.id,
        'rol_nombre': rol.nombre,
        'todos_permisos': todos_permisos,
        'permisos_asignados': permisos_asignados
    }
    return render(request, 'rol/roles_permisos_list.html', context)

@permiso_y_roles('change_usuario', roles=['Administrador'])
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
    return render(request, 'usuarios/permisos_usuario_form.html', context)