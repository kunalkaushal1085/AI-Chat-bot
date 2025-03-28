
from django.contrib import admin
from django.urls import path
from .views import *

urlpatterns = [
    path('generate-otp', GenerateOTPView.as_view(), name='generate-otp'),# Forgot email and generate otp same api work
    path('verify-otp', VerifyOTPView.as_view(), name='verify-otp'),
    path('customer-register', RegisterUserView.as_view(), name='customer_register'),
    path('forgot-password', ForgotPasswordView.as_view(), name='forgot-password'),
    path('customer-login', LoginView.as_view(), name='customer_login'),
    path('reset-password', VerifyOTPAndResetPasswordView.as_view(), name='reset-password'),
    path("update-profile", UserProfileView.as_view(), name="update-profiles"),
    path('create-workspace', WorkSpaceView.as_view(), name='create-workspace'),
   
]

