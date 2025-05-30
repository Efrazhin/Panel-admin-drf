from django.apps import AppConfig
from django.db.models.signals import post_migrate

class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'
    def ready(self):
        import users.signals
        from .signals import crear_permisos_signal
        post_migrate.connect(crear_permisos_signal, sender=self)