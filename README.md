Módulo de Autenticación para Django REST Framework
Este módulo ofrece una implementación completa, segura y profesional de autenticación basada en JWT para aplicaciones desarrolladas con Django REST Framework, utilizando SimpleJWT con tokens almacenados en cookies HttpOnly para mejorar la seguridad del frontend.

Características principales
🔐 Autenticación JWT robusta con SimpleJWT

🍪 Almacenamiento seguro de tokens en cookies HttpOnly (protección contra XSS)

🛡️ Implementación de protección CSRF y configuraciones de cookies SameSite

🔄 Soporte para refresh token automático y expiración configurable

🌐 API RESTful con endpoints para login, logout y renovación de tokens

🎨 Frontend básico en HTML y JavaScript para manejar login de manera sencilla

📋 Fácil integración en cualquier proyecto Django REST Framework

Instalación y configuración
Instalar las dependencias necesarias:

bash
Copiar
Editar
pip install djangorestframework djangorestframework-simplejwt django-cors-headers
Añadir las apps y middlewares en tu settings.py:

python
Copiar
Editar
INSTALLED_APPS = [
    ...
    'rest_framework',
    'corsheaders',
    # Agrega aquí la app de autenticación si la tienes separada
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    ...
]
Configurar DRF y SimpleJWT en settings.py:

python
Copiar
Editar
from datetime import timedelta

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'AUTH_COOKIE': 'access_token',  # Nombre cookie acceso
    'AUTH_COOKIE_REFRESH': 'refresh_token',  # Nombre cookie refresh
    'AUTH_COOKIE_DOMAIN': None,
    'AUTH_COOKIE_SECURE': False,  # Cambiar a True en producción con HTTPS
    'AUTH_COOKIE_HTTP_ONLY': True,
    'AUTH_COOKIE_PATH': '/',
    'AUTH_COOKIE_SAMESITE': 'Lax',
}
Configura CORS para permitir tu frontend:

python
Copiar
Editar
CORS_ALLOW_CREDENTIALS = True
CORS_ORIGIN_WHITELIST = [
    "http://localhost:8000",
    # Agrega tus URLs permitidas
]
Endpoints principales
Método	URL	Descripción
POST	/api/users/login/	Login con credenciales y obtención de tokens
POST	/api/users/logout/	Logout, elimina cookies
POST	/api/token/refresh/	Renovar token de acceso
GET	/api/users/me/	Obtener datos del usuario actual

Uso en frontend (JavaScript)
Ejemplo básico para login y manejo de cookies:

javascript
Copiar
Editar
async function login(email, password) {
  const response = await fetch('/api/users/login/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include', // Importante para enviar/recibir cookies
    body: JSON.stringify({ email, password }),
  });
  
  if (response.ok) {
    window.location.href = '/dashboard.html';
  } else {
    const errorData = await response.json();
    alert(errorData.non_field_errors || 'Error al iniciar sesión');
  }
}

async function logout() {
  await fetch('/api/users/logout/', {
    method: 'POST',
    credentials: 'include',
  });
  window.location.href = '/login.html';
}
Seguridad
Tokens almacenados en cookies HttpOnly para evitar acceso desde JavaScript (protección XSS).

Uso de SameSite en cookies para mitigar ataques CSRF.

Middleware de CSRF activo y configuración para APIs.

Renovación automática y rotación de tokens para minimizar riesgos.

HTTPS recomendado para asegurar las cookies en producción.

Requisitos
Python 3.8 o superior

Django 3.2 o superior

Django REST Framework 3.12 o superior

djangorestframework-simplejwt 5.0 o superior

django-cors-headers para manejo de CORS

Cómo contribuir
Por favor, consulta el archivo CONTRIBUTING.md para conocer las pautas de contribución, el flujo de trabajo con forks y pull requests, y buenas prácticas para colaborar.

Licencia
Este proyecto está licenciado bajo la Licencia MIT. Para más detalles, revisa el archivo LICENSE.