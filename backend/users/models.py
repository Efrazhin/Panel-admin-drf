from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)

    ROL_CHOICES = [
        ('admin', 'Administrador'),
        ('psicologo', 'Psicologo'),
        ('secretaria', 'Secretaria'),
    ]
    rol = models.CharField(max_length=20, choices=ROL_CHOICES)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return f"{self.username} ({self.get_rol_display()})"

# roles y permisos
class Permiso(models.Model):
    nombre = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.nombre


class Rol(models.Model):
    nombre = models.CharField(max_length=100, unique=True)
    permisos = models.ManyToManyField(Permiso, related_name='roles')

    def __str__(self):
        return self.nombre


class UsuarioRol(models.Model):
    usuario = models.ForeignKey('CustomUser', on_delete=models.CASCADE)
    rol = models.ForeignKey(Rol, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('usuario', 'rol')

    def __str__(self):
        return f'{self.usuario.username} - {self.rol.nombre}'
