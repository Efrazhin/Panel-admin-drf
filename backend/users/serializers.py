from rest_framework import serializers

from django.contrib.auth.models import Permission
from .models import Usuario, Rol



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
        # Verificar que password y password2 coincidan
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Las contraseñas no coinciden."})
        return attrs

    def create(self, validated_data):
        # Extraer y eliminar password2 del diccionario
        password = validated_data.pop('password')
        validated_data.pop('password2')
        # Extraer el objeto Rol
        rol_obj = validated_data.pop('rol')

        # Crear el usuario con username y email, asignar rol
        user = Usuario.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            rol=rol_obj

        )
        user.set_password(password)
        user.save()

        # 🔁 Convertimos 'psicologo' → 'Psicólogo' usando el dict de choices
        try:
            rol_nombre_legible = dict(CustomUser.ROL_CHOICES)[rol_nombre]
            rol = Rol.objects.get(nombre__iexact=rol_nombre_legible)
            UsuarioRol.objects.create(usuario=user, rol=rol)
        except Rol.DoesNotExist:
            raise serializers.ValidationError({"rol": f"Rol no válido: {rol_nombre}"})

        return user

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        # Mostrar el nombre legible del rol en la respuesta
        rep['rol'] = instance.rol.nombre if instance.rol else None
        return rep


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
    permisos_ids = serializers.ListField(
        child=serializers.IntegerField(),
        allow_empty=True
    )

class UsuarioPermisosUpdateSerializer(serializers.Serializer):
    permisos_ids = serializers.ListField(
        child=serializers.IntegerField(),
        allow_empty=True
    )
