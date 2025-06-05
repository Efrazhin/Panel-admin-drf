from django.db import models
from django.contrib.auth.models import AbstractUser, Permission

class Rol(models.Model):
    nombre = models.CharField(
        'Nombre del Rol',
        max_length=50,
        unique=True
    )
    permisos = models.ManyToManyField(
        Permission,
        blank=True,
        verbose_name='Permisos del Rol',
        help_text='Permisos asignados a este rol'
    )
    class Meta:
        default_permissions = ()
        permissions = [
            ('view_rol', 'Ver lista de roles'),
            ('add_rol', 'Crear nuevo rol'),
            ('change_rol', 'Modificar rol existente'),
            ('delete_rol', 'Eliminar rol'),
        ]
    def __str__(self):
        return self.nombre

class Usuario(AbstractUser):
    # Reemplazamos username field para loguear por email
    email = models.EmailField('Correo Electrónico', unique=True)
    rol = models.ForeignKey(
        Rol,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        verbose_name='Rol',
        help_text='Rol asociado al usuario'
    )
    permisos_adicionales = models.ManyToManyField(
        Permission,
        blank=True,
        verbose_name='Permisos Adicionales',
        help_text='Permisos concedidos puntualmente a este usuario'
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    class Meta:
        default_permissions = ()
        permissions = [
            ('view_usuario', 'Ver lista de usuarios'),
            ('add_usuario', 'Crear usuario'),
            ('change_usuario', 'Modificar usuario'),
            ('delete_usuario', 'Eliminar usuario'),
        ]

    def __str__(self):

        return self.email

    def get_roles(self):
        """
        Retorna lista con el rol actual (o lista vacía si no hay).
        """
        return [self.rol] if self.rol else []

    def get_all_permissions(self):
        """
        Devuelve un set con todos los objetos Permission
        que el usuario tiene, ya sea por su rol o por permisos_adicionales.
        """
        perms = set()
        if self.rol:
            perms.update(self.rol.permisos.all())
        perms.update(self.permisos_adicionales.all())
        return perms
        return f"{self.username} ({self.get_rol_display()})"

