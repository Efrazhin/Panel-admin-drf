from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
import requests

class JWTAuthenticationFromCookieMiddleware(MiddlewareMixin):
    def process_request(self, request):
        path = request.path

        EXCLUDE_PATHS = [
            '/users/api/login/',
            '/users/api/register/',
            '/users/api/refresh/',
            '/users/api/logout/',
            '/dashboard/login-page/',
        ]

        if any(path.endswith(exclude) for exclude in EXCLUDE_PATHS):
            return

        access_token = request.COOKIES.get('access_token')
        refresh_token = request.COOKIES.get('refresh_token')

        if access_token:
            try:
                AccessToken(access_token)
                request.META['HTTP_AUTHORIZATION'] = f'Bearer {access_token}'
            except TokenError:
                # access_token vencido, intentar renovar
                if refresh_token:
                    try:
                        response = requests.post(
                            'http://localhost:8000/users/api/refresh/',
                            json={'refresh': refresh_token}
                        )
                        if response.status_code == 200:
                            new_access_token = response.json()['access']
                            request.META['HTTP_AUTHORIZATION'] = f'Bearer {new_access_token}'
                            # Inyectar la nueva cookie para el response más tarde
                            request._new_access_token = new_access_token
                    except Exception as e:
                        print(f"Error renovando token: {str(e)}")  # Para debugging

    def process_response(self, request, response):
        if hasattr(request, '_new_access_token'):
            response.set_cookie(
                key='access_token',
                value=request._new_access_token,
                httponly=True,
                secure=False,
                samesite='Lax',
                path='/',
                max_age=3600  # 1 hora
            )
        return response
