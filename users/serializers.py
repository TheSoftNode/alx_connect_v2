from rest_framework import serializers

from users.models import CustomUser


class UserSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = CustomUser
        fields = ['password', 'email', 'first_name', 'last_name']
        extra_kwargs = {
            'password': {'write_only': True}, 
            'first_name': {'required': True},
            'last_name': {'required': True},
        }
