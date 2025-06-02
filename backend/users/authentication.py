from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.settings import api_settings
from django.utils.translation import gettext_lazy as _

class JWTFromCookieAuthentication(JWTAuthentication):
    """
    Extiende JWTAuthentication para leer el token de:
      1) Authorization header
      2) Si no está, de la cookie 'access_token'
    """

    def get_raw_token(self, header):
        # Intentar extraer de la cabecera Authorization
        raw_token = super().get_raw_token(header)
        if raw_token is not None:
            return raw_token

        # Si no hay en header, buscar en cookie
        request = self.context.get('request') if hasattr(self, 'context') else None
        if not request:
            return None
            
        token = request.COOKIES.get('access_token')
        if token:
            return token.encode('utf-8')  # Convertir a bytes como espera JWTAuthentication
        return None

    def authenticate(self, request):
        # Guardar request en el contexto para que get_raw_token lo use
        self.context = {'request': request}
        
        try:
            # Intentar autenticar
            auth_result = super().authenticate(request)
            if auth_result is not None:
                user, token = auth_result
                # Verificar si el usuario está activo
                if not user.is_active:
                    print("Usuario inactivo")  # Para debugging
                    return None
                return user, token
        except (InvalidToken, TokenError) as e:
            print(f"Error de token: {str(e)}")  # Para debugging
            return None
        except Exception as e:
            print(f"Error de autenticación: {str(e)}")  # Para debugging
            return None

        return None

    def authenticate_header(self, request):
        return 'Bearer'

    def get_validated_token(self, raw_token):
        """
        Validar el token y retornar el token validado.
        """
        try:
            return super().get_validated_token(raw_token)
        except Exception as e:
            print(f"Error validando token: {str(e)}")  # Para debugging
            raise InvalidToken(_('Token inválido o expirado'))
