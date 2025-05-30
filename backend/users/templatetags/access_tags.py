from django import template

register = template.Library()

@register.simple_tag(takes_context=True)
def ifperm(context, codename, true_val='', false_val=''):
    """
    Usage:
      {% ifperm "añadir_usuario" "<a>+</a>" "" %}
    Devuelve true_val si codename ∈ PERMISOS, sino false_val.
    """
    permisos = context.get('PERMISOS', [])
    return true_val if codename in permisos else false_val
