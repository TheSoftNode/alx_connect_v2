from rest_framework import serializers

from users.models import CustomUser


class UserSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = CustomUser
        fields = ['password', 'email', 'first_name', 'last_name', 'is_verified']
        extra_kwargs = {
            'password': {'write_only': True}, 
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

class VerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField()

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)