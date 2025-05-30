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
    password = serializers.CharField(write_only=True, required=True)
    roles = serializers.PrimaryKeyRelatedField(
        queryset=Rol.objects.all(), many=True, write_only=True, required=False
    )

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'password', 'roles']

    def create(self, validated_data):
        roles_data = validated_data.pop('roles', [])
        password = validated_data.pop('password')

        user = CustomUser(**validated_data)
        user.set_password(password)
        user.save()

        for rol in roles_data:
            UsuarioRol.objects.create(usuario=user, rol=rol)

        return user
    
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

    rol = serializers.SlugRelatedField(
        slug_field='nombre',
        queryset=Rol.objects.all(),
        write_only=True,
        required=True
    )

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password', 'password2', 'rol')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Las contraseñas no coinciden."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        rol_obj = validated_data.pop('rol')

        user = CustomUser.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
        )
        user.set_password(validated_data['password'])
        user.save()

        UsuarioRol.objects.create(usuario=user, rol=rol_obj)
        return user

    def to_representation(self, instance):
        usuario_rol = UsuarioRol.objects.filter(usuario=instance).first()
        rol_nombre = usuario_rol.rol.nombre if usuario_rol else None

        data = super().to_representation(instance)
        data['rol'] = rol_nombre
        return data