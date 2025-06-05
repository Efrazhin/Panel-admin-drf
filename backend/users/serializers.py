from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import Permission
from .models import Usuario, Rol
class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'codename', 'name', 'content_type']

class RolSerializer(serializers.ModelSerializer):
    permisos = PermissionSerializer(many=True, read_only=True)

    class Meta:
        model = Rol
        fields = ['id', 'nombre', 'permisos']

class UsuarioSerializer(serializers.ModelSerializer):
    rol = serializers.PrimaryKeyRelatedField(queryset=Rol.objects.all())
    permisos_adicionales = serializers.PrimaryKeyRelatedField(
        queryset=Permission.objects.all(),
        many=True,
        required=False
    )

    class Meta:
        model = Usuario
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'rol',
            'permisos_adicionales'
        ]


class RolPermisosUpdateSerializer(serializers.Serializer):
    permisos_ids = serializers.ListField(child=serializers.IntegerField(), allow_empty=True)

class UsuarioPermisosUpdateSerializer(serializers.Serializer):
    permisos_ids = serializers.ListField(child=serializers.IntegerField(), allow_empty=True)

class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=Usuario.objects.all())]
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
        write_only=True
    )

    class Meta:
        model = Usuario
        fields = ('username', 'email', 'password', 'password2', 'rol')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Las contraseñas no coinciden."})
        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password')
        validated_data.pop('password2')
        rol_obj = validated_data.pop('rol')

        user = Usuario.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            rol=rol_obj
        )
        user.set_password(password)
        user.save()
        return user

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['rol'] = instance.rol.nombre if instance.rol else None
        return rep




class UsuarioCreateUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer usado para Crear y Editar un Usuario, incluyendo contraseña.
    En edición, la contraseña es opcional (solo si vienen password/pwd2).
    """
    # Validar que el email sea único (en creación)
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=Usuario.objects.all())]
    )
    # Campos de contraseña (write_only para que no salgan en la respuesta)
    password = serializers.CharField(
        write_only=True,
        required=False,  # en edición no es obligatorio
        validators=[validate_password],
        style={"input_type": "password"}
    )
    password2 = serializers.CharField(
        write_only=True,
        required=False,  # en edición no es obligatorio
        style={"input_type": "password"}
    )

    class Meta:
        model = Usuario
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'rol',
            'permisos_adicionales',
            'password',
            'password2'
        ]

    def validate(self, attrs):
        # Si viene password (novedad), verificar que coincida con password2
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password or password2:
            if password != password2:
                raise serializers.ValidationError({"password": "Las contraseñas no coinciden."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2', None)
        password = validated_data.pop('password', None)

        user = Usuario.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            rol=validated_data.get('rol')
        )
        if password:
            user.set_password(password)
        else:
            # Si no se pasa password, podrías asignar uno por defecto o lanzar error, 
            # pero ideal es que siempre venga en creación
            user.set_unusable_password()
        user.save()

        # Si vienen permisos_adicionales
        permisos_ids = validated_data.get('permisos_adicionales', [])
        if permisos_ids:
            user.permisos_adicionales.set(permisos_ids)
        return user

    def update(self, instance, validated_data):
        # Remover password2
        validated_data.pop('password2', None)
        password = validated_data.pop('password', None)

        # Actualizar campos básicos
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.rol = validated_data.get('rol', instance.rol)

        if password:
            instance.set_password(password)

        instance.save()

        # Actualizar permisos adicionales, si vienen
        permisos_ids = validated_data.get('permisos_adicionales', None)
        if permisos_ids is not None:
            instance.permisos_adicionales.set(permisos_ids)

        return instance

