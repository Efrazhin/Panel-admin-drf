from django import template
from users.utils import usuario_tiene_permiso

register = template.Library()

@register.simple_tag(takes_context=True)
def has_perm(context, perm_codename):
    request = context.get('request')
    if not request:
        return False
    user = getattr(request, 'user', None)
    if not user:
        return False
    return usuario_tiene_permiso(user, perm_codename)
