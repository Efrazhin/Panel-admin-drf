# user/serializers.py

from rest_framework import serializers
from .models import *
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate



class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        user = authenticate(email=email, password=password)
        if not user:
            raise serializers.ValidationError("Credenciales incorrectas.")
        if not user.is_active:
            raise serializers.ValidationError("Este usuario está inactivo.")

        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'username': user.username,
            'email': user.email,
        }

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'is_active', 'is_staff', 'date_joined']


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=CustomUser.objects.all())]
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={"input_type": "password"}
    )
    password2 = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"}
    )
    rol = serializers.ChoiceField(choices=CustomUser.ROL_CHOICES, required=True)

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password', 'password2', 'rol')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Las contraseñas no coinciden."})
        return attrs

    def create(self, validated_data):
        rol_nombre = validated_data.get('rol')

        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            rol=rol_nombre  # esto sigue guardando 'admin', 'psicologo', etc.
        )
        user.set_password(validated_data['password'])
        user.save()

        # 🔁 Convertimos 'psicologo' → 'Psicólogo' usando el dict de choices
        try:
            rol_nombre_legible = dict(CustomUser.ROL_CHOICES)[rol_nombre]
            rol = Rol.objects.get(nombre__iexact=rol_nombre_legible)
            UsuarioRol.objects.create(usuario=user, rol=rol)
        except Rol.DoesNotExist:
            raise serializers.ValidationError({"rol": f"Rol no válido: {rol_nombre}"})

        return user


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
