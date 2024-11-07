# from rest_framework.decorators import api_view, authentication_classes, permission_classes
# from rest_framework.authentication import SessionAuthentication, TokenAuthentication
# from rest_framework.permissions import IsAuthenticated
# from rest_framework.response import Response
# from rest_framework import status

# from django.shortcuts import get_object_or_404
# from django.contrib.auth import get_user_model
# from rest_framework.authtoken.models import Token

# from users.serializers import UserSerializer, VerificationSerializer, PasswordResetRequestSerializer, PasswordResetConfirmSerializer, ChangePasswordSerializer

# from drf_yasg.utils import swagger_auto_schema
# from drf_yasg import openapi


# user_properties = {
#     'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
#     'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='User first name'),
#     'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='User last name'),
#     'verification_code': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit verification code'),
# }

# error_response = openapi.Schema(
#     type=openapi.TYPE_OBJECT,
#     properties={
#         'error': openapi.Schema(type=openapi.TYPE_STRING, description='Error message'),
#     }
# )

# success_message_response = openapi.Schema(
#     type=openapi.TYPE_OBJECT,
#     properties={
#         'message': openapi.Schema(type=openapi.TYPE_STRING, description='Success message'),
#     }
# )

# success_password_reset = openapi.Schema(
#     type=openapi.TYPE_OBJECT,
#     properties={
#         'message': openapi.Schema(type=openapi.TYPE_STRING, description='Success message'),
#         'reset_password_token': openapi.Schema(type=openapi.TYPE_STRING, description='Password reset token'),
#     }
# )

# # /sign
# signup_response = openapi.Schema(
#     type=openapi.TYPE_OBJECT,
#     properties={
#         'token': openapi.Schema(type=openapi.TYPE_STRING, description='Authentication token'),
#         'user': openapi.Schema(
#             type=openapi.TYPE_OBJECT,
#             properties={
#                 **user_properties,
#             }
#         ),
#         'message': openapi.Schema(type=openapi.TYPE_STRING, description='Verification instructions'),
#     }
# )

# @swagger_auto_schema(
#     method='post',
#     request_body=openapi.Schema(
#         type=openapi.TYPE_OBJECT,
#         required=['email', 'password', 'first_name', 'last_name'],
#         properties={
#             'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
#             'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
#             'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='User first name'),
#             'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='User last name'),
#         }
#     ),
#     responses={
#         200: signup_response,
#         400: error_response,
#     },
#     operation_description="Create a new user account and send verification email",
# )

# @api_view(['POST'])
# def signup(request):
#     serializer = UserSerializer(data=request.data)
#     if serializer.is_valid():
#         serializer.save()
#         user = get_user_model().objects.get(email=request.data['email'])
#         user.set_password(request.data['password'])
#         user.first_name = request.data['first_name']  
#         user.last_name = request.data['last_name']   
#         user.send_verification_email()
#         user.save()
#         token = Token.objects.create(user=user)
#         return Response({
#             'token': token.key,
#             'user': {
#                 'email': user.email,
#                 'first_name': user.first_name,
#                 'last_name': user.last_name,
#                 'verification_code': user.verification_code,
#                 **serializer.data
#             },
#             'message': 'Please check your email for verification code'
#         })
#     print(serializer.errors)
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# # /verify-email
# @swagger_auto_schema(
#     method='post',
#     request_body=openapi.Schema(
#         type=openapi.TYPE_OBJECT,
#         required=['email', 'verification_code'],
#         properties={
#             'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
#             'verification_code': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit verification code sent to email'),
#         }
#     ),
#     responses={
#         200: success_message_response,
#         400: error_response,
#     },
#     operation_description="Verify user email address using the verification code",
# )

# @api_view(['POST'])
# def verify_email(request):
#     serializer = VerificationSerializer(data=request.data)
#     if serializer.is_valid():
#         try:
#             user = get_user_model().objects.get(
#                 email=serializer.validated_data['email'],
#                 verification_code=serializer.validated_data['verification_code']
#             )
#             user.is_verified = True
#             user.verification_code = None
#             user.save()
#             return Response({'message': 'Email verified successfully'})
#         except get_user_model().DoesNotExist:
#             return Response(
#                 {'error': 'Invalid verification code'},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# @swagger_auto_schema(
#     method='post',
#     request_body=openapi.Schema(
#         type=openapi.TYPE_OBJECT,
#         required=['email'],
#         properties={
#             'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
#         }
#     ),
#     responses={
#         200: openapi.Schema(
#             type=openapi.TYPE_OBJECT,
#             properties={
#                 'verification_code': openapi.Schema(type=openapi.TYPE_STRING, description='New verification code'),
#                 'message': openapi.Schema(type=openapi.TYPE_STRING, description='Success message'),
#             }
#         ),
#         400: openapi.Schema(
#             type=openapi.TYPE_OBJECT,
#             properties={
#                 'error': openapi.Schema(type=openapi.TYPE_STRING, description='Error message'),
#             }
#         ),
#     },
#     operation_description="Resend verification code to user's email address"
# )


# @api_view(['POST'])
# def resend_verification(request):
#     email = request.data.get('email')
    
#     if not email:
#         return Response(
#             {'error': 'Email is required'}, 
#             status=status.HTTP_400_BAD_REQUEST
#         )
    
#     try:
#         user = get_object_or_404(get_user_model(), email=email)
        
#         if user.is_verified:
#             return Response(
#                 {'error': 'User is already verified'},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
            
#         user.send_verification_email()
#         user.save()
        
#         return Response({
#             'verification_code': user.verification_code,
#             'message': 'Verification code has been resent to your email'
#         })
        
#     except get_user_model().DoesNotExist:
#         return Response(
#             {'error': 'User with this email does not exist'},
#             status=status.HTTP_400_BAD_REQUEST
#         )


# @swagger_auto_schema(
#     method='post',
#     request_body=openapi.Schema(
#         type=openapi.TYPE_OBJECT,
#         required=['email', 'password'],
#         properties={
#             'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
#             'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
#         }
#     ),
#     responses={
#         200: openapi.Schema(
#             type=openapi.TYPE_OBJECT,
#             properties={
#                 'token': openapi.Schema(type=openapi.TYPE_STRING, description='Authentication token'),
#                 'user': openapi.Schema(
#                     type=openapi.TYPE_OBJECT,
#                     properties=user_properties,
#                 ),
#             }
#         ),
#         404: openapi.Schema(type=openapi.TYPE_STRING, description='User not found or invalid credentials'),
#         403: openapi.Schema(type=openapi.TYPE_STRING, description='User not verified'),
#     },
#     operation_description="Authenticate user and retrieve token",
# )

# @api_view(['POST'])
# def login(request):
#     user = get_object_or_404(get_user_model(), email=request.data['email'])
    
#     # Check password first
#     if not user.check_password(request.data['password']):
#         return Response("Invalid credentials", status=status.HTTP_404_NOT_FOUND)
    
#     # Check if user is verified
#     if not user.is_verified:
#         return Response("Account not verified", status=status.HTTP_403_FORBIDDEN)
    
#     token, created = Token.objects.get_or_create(user=user)
#     serializer = UserSerializer(user)
#     return Response({'token': token.key, 'user': serializer.data})



# # Test token endpoint
# @swagger_auto_schema(
#     method='get',
#     manual_parameters=[
#         openapi.Parameter(
#             'Authorization',
#             openapi.IN_HEADER,
#             description='Token {your_token_here}',
#             type=openapi.TYPE_STRING,
#             required=True
#         ),
#     ],
#     responses={
#         200: openapi.Schema(type=openapi.TYPE_STRING, description='Token verification response'),
#         401: 'Authentication credentials were not provided',
#     },
#     operation_description="Test if authentication token is valid",
# )

# @api_view(['GET'])
# @authentication_classes([SessionAuthentication, TokenAuthentication])
# @permission_classes([IsAuthenticated])
# def test_token(request):
#     return Response("passed!")



# # Request password reset endpoint
# @swagger_auto_schema(
#     method='post',
#     request_body=openapi.Schema(
#         type=openapi.TYPE_OBJECT,
#         required=['email'],
#         properties={
#             'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
#         }
#     ),

    
#     responses={
#         200: success_password_reset,
#         404: error_response,
#         400: error_response,
#     },
#     operation_description="Request a password reset token via email",
# )

# @api_view(['POST'])
# def request_password_reset(request):
#     serializer = PasswordResetRequestSerializer(data=request.data)
#     if serializer.is_valid():
#         try:
#             user =  get_user_model().objects.get(email=serializer.validated_data['email'])
#             user.send_reset_password_email()
#             return Response({
#                 'message': 'Password reset email sent',
#                 'reset_password_token': user.reset_password_token
#                 })
#         except  get_user_model().DoesNotExist:
#             return Response(
#                 {'error': 'User not found'},
#                 status=status.HTTP_404_NOT_FOUND
#             )
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# # Reset password endpoint
# @swagger_auto_schema(
#     method='post',
#     request_body=openapi.Schema(
#         type=openapi.TYPE_OBJECT,
#         required=['email', 'token', 'new_password'],
#         properties={
#             'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
#             'token': openapi.Schema(type=openapi.TYPE_STRING, description='Password reset token received via email'),
#             'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='New password'),
#         }
#     ),
#     responses={
#         200: success_message_response,
#         400: error_response,
#     },
#     operation_description="Reset password using the token received via email",
# )

# @api_view(['POST'])
# def reset_password(request):
#     serializer = PasswordResetConfirmSerializer(data=request.data)
#     if serializer.is_valid():
#         try:
#             user =  get_user_model().objects.get(
#                 email=serializer.validated_data['email'],
#                 reset_password_token=serializer.validated_data['token']
#             )
#             user.set_password(serializer.validated_data['new_password'])
#             user.reset_password_token = None
#             user.save()
#             return Response({'message': 'Password reset successful'})
#         except  get_user_model().DoesNotExist:
#             return Response(
#                 {'error': 'Invalid token'},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# # Change password endpoint
# @swagger_auto_schema(
#     method='post',
#     manual_parameters=[
#         openapi.Parameter(
#             'Authorization',
#             openapi.IN_HEADER,
#             description='Token {your_token_here}',
#             type=openapi.TYPE_STRING,
#             required=True
#         ),
#     ],
#     request_body=openapi.Schema(
#         type=openapi.TYPE_OBJECT,
#         required=['old_password', 'new_password'],
#         properties={
#             'old_password': openapi.Schema(type=openapi.TYPE_STRING, description='Current password'),
#             'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='New password'),
#         }
#     ),
#     responses={
#         200: success_message_response,
#         400: error_response,
#         401: 'Authentication credentials were not provided',
#     },
#     operation_description="Change password for authenticated user",
# )

# @api_view(['POST'])
# @authentication_classes([SessionAuthentication, TokenAuthentication])
# @permission_classes([IsAuthenticated])
# def change_password(request):
#     serializer = ChangePasswordSerializer(data=request.data)
#     if serializer.is_valid():
#         user = request.user
#         if user.check_password(serializer.validated_data['old_password']):
#             user.set_password(serializer.validated_data['new_password'])
#             user.save()
#             return Response({'message': 'Password changed successfully'})
#         return Response(
#             {'error': 'Invalid old password'},
#             status=status.HTTP_400_BAD_REQUEST
#         )
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from django.utils import timezone
from .models import RefreshUserToken


from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model

from users.serializers import UserSerializer, VerificationSerializer, PasswordResetRequestSerializer, PasswordResetConfirmSerializer, ChangePasswordSerializer

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

user_properties = {
    'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
    'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='User first name'),
    'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='User last name'),
    'verification_code': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit verification code'),
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

success_password_reset = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'message': openapi.Schema(type=openapi.TYPE_STRING, description='Success message'),
        'reset_password_token': openapi.Schema(type=openapi.TYPE_STRING, description='Password reset token'),
    }
)

signup_response = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'access': openapi.Schema(type=openapi.TYPE_STRING, description='Access token'),
        'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token'),
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
# @permission_classes([AllowAny])
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
        refresh = RefreshToken.for_user(user)
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': {
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'verification_code': user.verification_code,
                **serializer.data
            },
            'message': 'Please check your email for verification code'
        })
    print(serializer.errors)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
        required=['email'],
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
        }
    ),
    responses={
        200: openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'verification_code': openapi.Schema(type=openapi.TYPE_STRING, description='New verification code'),
                'message': openapi.Schema(type=openapi.TYPE_STRING, description='Success message'),
            }
        ),
        400: openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'error': openapi.Schema(type=openapi.TYPE_STRING, description='Error message'),
            }
        ),
    },
    operation_description="Resend verification code to user's email address"
)


@api_view(['POST'])
def resend_verification(request):
    email = request.data.get('email')
    
    if not email:
        return Response(
            {'error': 'Email is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        user = get_object_or_404(get_user_model(), email=email)
        
        if user.is_verified:
            return Response(
                {'error': 'User is already verified'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        user.send_verification_email()
        user.save()
        
        return Response({
            'verification_code': user.verification_code,
            'message': 'Verification code has been resent to your email'
        })
        
    except get_user_model().DoesNotExist:
        return Response(
            {'error': 'User with this email does not exist'},
            status=status.HTTP_400_BAD_REQUEST
        )


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
                'access': openapi.Schema(type=openapi.TYPE_STRING, description='Access token'),
                'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token'),
                'user': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties=user_properties,
                ),
            }
        ),
        404: openapi.Schema(type=openapi.TYPE_STRING, description='User not found or invalid credentials'),
        403: openapi.Schema(type=openapi.TYPE_STRING, description='User not verified'),
    },
    operation_description="Authenticate user and retrieve tokens",
)

@api_view(['POST'])
def login(request):
    user = get_object_or_404(get_user_model(), email=request.data['email'])
    
    # Check password
    if not user.check_password(request.data['password']):
        return Response("Invalid credentials", status=status.HTTP_404_NOT_FOUND)
    
    # Check if user is verified
    if not user.is_verified:
        return Response("Account not verified", status=status.HTTP_403_FORBIDDEN)
    
    # Generate access and refresh tokens
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)
    
    # Calculate expiration time using the token's lifetime
    expires_at = timezone.now() + refresh.lifetime
    
    # Store the refresh token in the database
    RefreshUserToken.objects.create(user=user, token=refresh_token, expires_at=expires_at, revoked=False)
    
    serializer = UserSerializer(user)
    return Response({
        'access': access_token,
        'refresh': refresh_token,
        'user': serializer.data
    })


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
        200: success_password_reset,
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
            return Response({
                'message': 'Password reset email sent',
                'reset_password_token': user.reset_password_token
                })
        except  get_user_model().DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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


@swagger_auto_schema(
    method='post',
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            openapi.IN_HEADER,
            description='Bearer {your_access_token}',
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
# @authentication_classes([JWTAuthentication])
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

# Test token endpoint
@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            openapi.IN_HEADER,
            description='Bearer {your_token_here}',
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
# @authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response("passed!")


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['refresh'],
        properties={
            'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token'),
        }
    ),
    responses={
        200: openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'access': openapi.Schema(type=openapi.TYPE_STRING, description='New access token'),
            }
        ),
        400: openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'error': openapi.Schema(type=openapi.TYPE_STRING, description='Error message'),
            }
        ),
    },
    operation_description="Refresh access token using the refresh token",
)
@api_view(['POST'])
def token_refresh(request):
    serializer = TokenRefreshSerializer(data=request.data)

    try:
        serializer.is_valid(raise_exception=True)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # Check if the refresh token is valid and exists in the database
    refresh_token = serializer.validated_data['refresh']
    try:
        refresh_token_obj = RefreshUserToken.objects.get(token=refresh_token, revoked=False, expires_at__gt=timezone.now())
    except RefreshUserToken.DoesNotExist:
        return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

    # Generate a new access token
    refresh = RefreshToken(refresh_token_obj.token)
    new_access_token = str(refresh.access_token)

    # Calculate expiration time using the token's lifetime
    expires_at = timezone.now() + refresh.lifetime

    # Update the refresh token expiration
    refresh_token_obj.expires_at = timezone.now() + expires_at
    refresh_token_obj.save()

    return Response({'access': new_access_token})


@swagger_auto_schema(
    method='post',
    operation_description="Logout the authenticated user by revoking their active refresh token.",
    responses={
        200: openapi.Response(
            description="Successfully logged out",
            examples={"application/json": {"message": "Logged out successfully"}}
        ),
        401: openapi.Response(
            description="Authentication credentials were not provided."
        ),
    },
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        refresh_token = RefreshToken.objects.get(user=request.user, revoked=False)
        refresh_token.revoked = True
        refresh_token.save()
    except RefreshToken.DoesNotExist:
        pass

    return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)
