from django.contrib import admin
from django.shortcuts import redirect
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),

    # Rutas de la app users (API)
    path('users/', include('users.urls')),

    # Rutas de la app dashboard (templates HTML)
    path('dashboard/', include('dashboard.urls')),

    # Redirigir la raíz a la página de login de dashboard
    path('', lambda request: redirect('login')),
]
