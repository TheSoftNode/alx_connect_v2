from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
import random


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field is required")
        if not extra_fields.get('first_name'):
            raise ValueError("The First Name field is required")
        if not extra_fields.get('last_name'):
            raise ValueError("The Last Name field is required")
            
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)



class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(_('email address'), unique=True)
    first_name = models.CharField(_('first name'), max_length=150, blank=False)  
    last_name = models.CharField(_('last name'), max_length=150, blank=False)   
    is_verified = models.BooleanField(default=False)
    verification_code = models.CharField(max_length=6, null=True, blank=True)
    reset_password_token = models.CharField(max_length=100, null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['password', 'first_name', 'last_name'] 

    objects = CustomUserManager()

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def __str__(self):
        return f"{self.first_name} {self.last_name} <{self.email}>"

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def get_short_name(self):
        return self.first_name
    
    def send_verification_email(self):
        # Generate a random verification code
        code = ''.join(random.choices('0123456789', k=6))
        self.verification_code = code
        self.save()

        # Prepare email subject
        subject = 'Verify Your Email'

        # Prepare HTML content for the email
        html_content = render_to_string('emails/verification_email.html', {'verification_code': code})

        # Create the email message
        email = EmailMessage(
            subject,
            html_content,
            settings.DEFAULT_FROM_EMAIL,  
            [self.email],  # Recipient's email
        )
        email.content_subtype = 'html'  # Make the email HTML formatted
        email.send(fail_silently=False)

    def send_reset_password_email(self):
        token = default_token_generator.make_token(self)
        self.reset_password_token = token
        self.save()
        
        send_mail(
            'Reset Your Password',
            f'Use this token to reset your password: {token}',
            settings.DEFAULT_FROM_EMAIL,
            [self.email],
            fail_silently=False,
        )

class RefreshUserToken(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='refresh_tokens')
    token = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)

    def __str__(self):
        return f"Token for {self.user.email} (Revoked: {self.revoked})"