from django.shortcuts import render
from django.contrib.auth import get_user_model
from  rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from rest_framework.authtoken.models import Token
from .models import OTP
from .serializers import UserRegistrationSerializer
from dotenv import load_dotenv
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.permissions import AllowAny
from django.utils import timezone
from django.contrib.auth.hashers import make_password
import random
from datetime import timedelta
import os
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
import string
from .serializers import *

load_dotenv()



def get_base_url(request):
    """
    Helper function to generate the base URL for API (e.g., http://localhost:8000/api/).
    """
    return f"{request.scheme}://{request.get_host()}"


# Generate OTP and send it via email
class GenerateOTPView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"status":status.HTTP_400_BAD_REQUEST,"message": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        if not self.is_valid_email(email):
            return Response({"status":status.HTTP_400_BAD_REQUEST,"message": "Invalid email format."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Check if OTP already exists and has expired
            otp = OTP.objects.filter(email=email).first()
            # If OTP exists and is still valid (within 60 seconds), don't generate a new OTP
            if otp and otp.expired_at > timezone.now():
                return Response({"status":status.HTTP_400_BAD_REQUEST,"message": "OTP already sent. Please check your email."}, status=status.HTTP_400_BAD_REQUEST)

            # Generate a new OTP
            otp_code = str(random.randint(1000, 9999))
            expiration_time = timezone.now() + timedelta(seconds=60)
            # If OTP exists, update the existing OTP, otherwise create a new OTP
            if otp:
                otp.otp_code = otp_code
                otp.expired_at = expiration_time
                otp.save()
            else:
                otp = OTP.objects.create(email=email, otp_code=otp_code, expired_at=expiration_time)
            try:
                # Send OTP via email
                # send_mail(
                #     "Your OTP Code",              
                #     f"Your OTP code is: {otp_code}", 
                #     settings.EMAIL_HOST_USER,            
                #     [email],                        
                #     fail_silently=False,     
                # )
                return Response({"status":status.HTTP_200_OK,"message": "OTP sent to your email.","otp": otp_code}, status=status.HTTP_200_OK)

            except Exception as e:
                return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"message": f"Failed to send OTP email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ObjectDoesNotExist:
            # Handle database related issues, if any
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"message": "Unable to process the OTP request. Please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            # Handle any unexpected errors
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"messsage": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def is_valid_email(self, email):
        # Basic check for email format
        return "@" in email and "." in email

User = get_user_model()
# Verify OTP and create user
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp_code = request.data.get('otp_code')
        if not email:
            return Response({"status":status.HTTP_400_BAD_REQUEST,"message": "Email are required."}, status=400)
        try:
            otp_instance = OTP.objects.filter(email=email, otp_code=otp_code, is_verified=False).latest('created_at')
            if not otp_instance:
                return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Invalid or expired OTP."}, status=400)
            if otp_instance.otp_code != otp_code:
                return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Invalid OTP."}, status=400)

            # Check if OTP is expired
            current_time = timezone.now()
            if current_time > otp_instance.created_at + timezone.timedelta(seconds=60):
                # If OTP expired, mark it as verified (to prevent reuse) and inform the user
                otp_instance.is_verified = True
                otp_instance.save()
                return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "OTP has expired. Please request a new OTP."}, status=400)

            # Mark OTP as verified and save
            otp_instance.is_verified = True
            otp_instance.save()

            return Response({"status":status.HTTP_200_OK,"message": "OTP verified successfully."}, status=200)

        except Exception as e:
            return Response({"status":status.HTTP_400_BAD_REQUEST,"message": f"Invalid or expired OTP.{e}"}, status=400)
        
# Create user
class RegisterUserView(APIView):

    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            print(password,'password')
            if not email:
                return Response({"status":status.HTTP_400_BAD_REQUEST,"message": "Email are required."}, status=400)
            if not password:
                return Response({"status":status.HTTP_400_BAD_REQUEST,"message": "password are required."}, status=400)
            if not OTP.objects.filter(email=email, is_verified=True).exists():
                return Response({"status":status.HTTP_400_BAD_REQUEST,"message": "OTP not verified for this email."}, status=400)
            # Check if email is unique
            if User.objects.filter(email=email).exists():
                return Response({"status":status.HTTP_400_BAD_REQUEST,"message": "Email is already registered."}, status=400)

            # Create and save the user
            user = User.objects.create_user(username=email, email=email, password=password)

            return Response({"status":status.HTTP_200_OK,"message": "User registered successfully."}, status=201)
        except Exception as e:
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"message":str(e)})
    
    
class LoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self,request):
        email = request.data.get('email')
        password = request.data.get('password')
        if not email:
            return Response({"status":status.HTTP_400_BAD_REQUEST,"message": "Email are required."}, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({"status":status.HTTP_400_BAD_REQUEST,"message": "password are required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = authenticate(request,username=email,password=password)
            if user is None:
                return Response({"status":status.HTTP_401_UNAUTHORIZED,"message": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)
            if not user.check_password(password):
                return Response({"status":status.HTTP_401_UNAUTHORIZED,"message": "Invalid password."}, status=status.HTTP_401_UNAUTHORIZED)
            # If user is found, create a token (or get existing one)
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                "status": status.HTTP_200_OK,
                "message": "Login successful.",
                "token": token.key,
                "base_url":get_base_url(request)
            }, status=status.HTTP_200_OK)
        except Exception as e:
            print(str(e))
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"message": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPAndResetPasswordView(APIView): 
    def post(self, request):
        try:
            email = request.data.get("email")
            password = request.data.get("password")

            # ✅ Step 1: Check if email are provided
            if not email:
                return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Email are required."}, 
                                status=status.HTTP_400_BAD_REQUEST)
                
            if not password :
                    return Response({
                        "status": status.HTTP_200_OK,
                        "message": "password is required."
                    }, status=status.HTTP_200_OK)

            # ✅ Step 4: Update user's password
            user = User.objects.filter(email=email).first()
            if not user:
                return Response({"status": status.HTTP_404_NOT_FOUND, "message": "User not found."}, 
                                status=status.HTTP_404_NOT_FOUND)

            user.password = make_password(password)  # Hash the password before saving
            user.save()

            return Response({
                "status": status.HTTP_200_OK,
                "message": "Password reset successfully."
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"message":str(e)})
        

#Profile APi
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self,request):
        try:
            user = request.user
            name = request.data.get("name")
            business_type = request.POST.get("business_type", "")
            primary_goal = request.POST.get("primary_goal", "")
            if not name:
                return Response({"status":status.HTTP_400_BAD_REQUEST,"message":"Name is Requried"},status.HTTP_400_BAD_REQUEST)
            business_type_str = ",".join([bt.strip() for bt in business_type.split(",") if bt.strip()])
            primary_goal_str = ",".join([pg.strip() for pg in primary_goal.split(",") if pg.strip()])
            # Create or update user profile
            profile, created = UserProfile.objects.update_or_create(
                user=user,
                defaults={"name": name, "business_type": business_type_str, "primary_goal": primary_goal_str},
            )
            message = "Profile created successfully." if created else "Profile updated successfully."
            return Response(
                {"status":status.HTTP_200_OK,"message": message, "profile": UserProfileSerializer(profile).data},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"message":str(e)})