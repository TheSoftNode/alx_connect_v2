from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

from users.serializers import UserSerializer

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

response_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'token': openapi.Schema(type=openapi.TYPE_STRING, description='Authentication token'),
        'user': openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING),
            }
        )
    }
)

@swagger_auto_schema(
    method='post',
    request_body=UserSerializer,
    responses={
        200: response_schema,
        400: 'Invalid data'
    }
)

@api_view(['POST'])
def signup(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        user = get_user_model().objects.get(email=request.data['email'])
        user.set_password(request.data['password'])
        user.first_name = request.data['first_name']  
        user.last_name = request.data['last_name']   
        user.save()
        token = Token.objects.create(user=user)
        return Response({
            'token': token.key,
            'user': {
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                **serializer.data
            }
        })
    print(serializer.errors)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def login(request):
    user = get_object_or_404(get_user_model(), email=request.data['email'])
    print(user)
    if not user.check_password(request.data['password']):
        return Response("missing user", status=status.HTTP_404_NOT_FOUND)
    token, created = Token.objects.get_or_create(user=user)
    serializer = UserSerializer(user)
    return Response({'token': token.key, 'user': serializer.data})


@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response("passed!")
