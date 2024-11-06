from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

from users.serializers import UserSerializer, VerificationSerializer, PasswordResetRequestSerializer, PasswordResetConfirmSerializer, ChangePasswordSerializer

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


user_properties = {
    'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
    'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='User first name'),
    'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='User last name'),
}

error_response = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'error': openapi.Schema(type=openapi.TYPE_STRING, description='Error message'),
    }
)

success_message_response = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'message': openapi.Schema(type=openapi.TYPE_STRING, description='Success message'),
    }
)

# /sign
signup_response = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'token': openapi.Schema(type=openapi.TYPE_STRING, description='Authentication token'),
        'user': openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                **user_properties,
            }
        ),
        'message': openapi.Schema(type=openapi.TYPE_STRING, description='Verification instructions'),
    }
)

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email', 'password', 'first_name', 'last_name'],
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
            'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='User first name'),
            'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='User last name'),
        }
    ),
    responses={
        200: signup_response,
        400: error_response,
    },
    operation_description="Create a new user account and send verification email",
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
        user.send_verification_email()
        user.save()
        token = Token.objects.create(user=user)
        return Response({
            'token': token.key,
            'user': {
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                **serializer.data
            },
            'message': 'Please check your email for verification code'
        })
    print(serializer.errors)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# /verify-email
@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email', 'verification_code'],
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
            'verification_code': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit verification code sent to email'),
        }
    ),
    responses={
        200: success_message_response,
        400: error_response,
    },
    operation_description="Verify user email address using the verification code",
)

@api_view(['POST'])
def verify_email(request):
    serializer = VerificationSerializer(data=request.data)
    if serializer.is_valid():
        try:
            user = get_user_model().objects.get(
                email=serializer.validated_data['email'],
                verification_code=serializer.validated_data['verification_code']
            )
            user.is_verified = True
            user.verification_code = None
            user.save()
            return Response({'message': 'Email verified successfully'})
        except get_user_model().DoesNotExist:
            return Response(
                {'error': 'Invalid verification code'},
                status=status.HTTP_400_BAD_REQUEST
            )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email', 'password'],
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
        }
    ),
    responses={
        200: openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'token': openapi.Schema(type=openapi.TYPE_STRING, description='Authentication token'),
                'user': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties=user_properties,
                ),
            }
        ),
        404: openapi.Schema(type=openapi.TYPE_STRING, description='User not found or invalid credentials'),
        403: openapi.Schema(type=openapi.TYPE_STRING, description='User not verified'),
    },
    operation_description="Authenticate user and retrieve token",
)

@api_view(['POST'])
def login(request):
    user = get_object_or_404(get_user_model(), email=request.data['email'])
    
    # Check password first
    if not user.check_password(request.data['password']):
        return Response("Invalid credentials", status=status.HTTP_404_NOT_FOUND)
    
    # Check if user is verified
    if not user.verified:
        return Response("Account not verified", status=status.HTTP_403_FORBIDDEN)
    
    token, created = Token.objects.get_or_create(user=user)
    serializer = UserSerializer(user)
    return Response({'token': token.key, 'user': serializer.data})



# Test token endpoint
@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            openapi.IN_HEADER,
            description='Token {your_token_here}',
            type=openapi.TYPE_STRING,
            required=True
        ),
    ],
    responses={
        200: openapi.Schema(type=openapi.TYPE_STRING, description='Token verification response'),
        401: 'Authentication credentials were not provided',
    },
    operation_description="Test if authentication token is valid",
)

@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response("passed!")



# Request password reset endpoint
@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email'],
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
        }
    ),
    responses={
        200: success_message_response,
        404: error_response,
        400: error_response,
    },
    operation_description="Request a password reset token via email",
)

@api_view(['POST'])
def request_password_reset(request):
    serializer = PasswordResetRequestSerializer(data=request.data)
    if serializer.is_valid():
        try:
            user =  get_user_model().objects.get(email=serializer.validated_data['email'])
            user.send_reset_password_email()
            return Response({'message': 'Password reset email sent'})
        except  get_user_model().DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Reset password endpoint
@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email', 'token', 'new_password'],
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
            'token': openapi.Schema(type=openapi.TYPE_STRING, description='Password reset token received via email'),
            'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='New password'),
        }
    ),
    responses={
        200: success_message_response,
        400: error_response,
    },
    operation_description="Reset password using the token received via email",
)

@api_view(['POST'])
def reset_password(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)
    if serializer.is_valid():
        try:
            user =  get_user_model().objects.get(
                email=serializer.validated_data['email'],
                reset_password_token=serializer.validated_data['token']
            )
            user.set_password(serializer.validated_data['new_password'])
            user.reset_password_token = None
            user.save()
            return Response({'message': 'Password reset successful'})
        except  get_user_model().DoesNotExist:
            return Response(
                {'error': 'Invalid token'},
                status=status.HTTP_400_BAD_REQUEST
            )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Change password endpoint
@swagger_auto_schema(
    method='post',
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            openapi.IN_HEADER,
            description='Token {your_token_here}',
            type=openapi.TYPE_STRING,
            required=True
        ),
    ],
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['old_password', 'new_password'],
        properties={
            'old_password': openapi.Schema(type=openapi.TYPE_STRING, description='Current password'),
            'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='New password'),
        }
    ),
    responses={
        200: success_message_response,
        400: error_response,
        401: 'Authentication credentials were not provided',
    },
    operation_description="Change password for authenticated user",
)

@api_view(['POST'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def change_password(request):
    serializer = ChangePasswordSerializer(data=request.data)
    if serializer.is_valid():
        user = request.user
        if user.check_password(serializer.validated_data['old_password']):
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({'message': 'Password changed successfully'})
        return Response(
            {'error': 'Invalid old password'},
            status=status.HTTP_400_BAD_REQUEST
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


