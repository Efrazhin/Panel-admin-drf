from django.db import models
from django.contrib.auth.models import AbstractUser

class Permiso(models.Model):
    codename = models.CharField(
        max_length=100,
        unique=True,
        help_text="Código único del permiso, ej. 'crear_usuario'"
    )
    nombre = models.CharField(
        max_length=150,
        help_text="Nombre legible del permiso, ej. 'Crear Usuario'"
    )

    def __str__(self):
        return self.nombre

class Rol(models.Model):
    nombre = models.CharField(
        max_length=100,
        unique=True,
        help_text="Nombre del rol, ej. 'admin', 'secretaria'"
    )
    permisos = models.ManyToManyField(
        Permiso,
        related_name='roles',
        blank=True,
        help_text="Permisos asociados a este rol"
    )

    def __str__(self):
        return self.nombre

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return f"{self.username} ({self.email})"

    def get_roles(self):
        """Devuelve los roles asignados al usuario."""
        return Rol.objects.filter(rol_usuarios__usuario=self)


    def get_permisos(self):
        """Devuelve lista de codenames de permisos únicos de todos sus roles."""
        return list(
        Permiso.objects.filter(
            roles__in=self.get_roles()
        ).values_list('codename', flat=True).distinct()
    )


class UsuarioRol(models.Model):
    usuario = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='usuario_roles',
        help_text="Usuario asociado al rol"
    )
    rol = models.ForeignKey(
        Rol,
        on_delete=models.CASCADE,
        related_name='rol_usuarios',
        help_text="Rol asignado al usuario"
    )

    class Meta:
        unique_together = ('usuario', 'rol')
        verbose_name = 'Asignación de Rol'
        verbose_name_plural = 'Asignaciones de Roles'

    def __str__(self):
        return f'{self.usuario.username} - {self.rol.nombre}'
