from django.urls import re_path

from . import views

urlpatterns = [
    re_path('signup', views.signup),
    re_path('login', views.login),
    re_path('test_token', views.test_token),
    re_path('verify-email/', views.verify_email, name='verify-email'),
    re_path('request-password-reset/', views.request_password_reset, name='request-password-reset'),
    re_path('reset-password/', views.reset_password, name='reset-password'),
    re_path('change-password/', views.change_password, name='change-password'),
]