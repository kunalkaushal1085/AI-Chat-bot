from django.shortcuts import render
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
            return Response({"status":status.HTTP_400_BAD_REQUEST,"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        if not self.is_valid_email(email):
            return Response({"status":status.HTTP_400_BAD_REQUEST,"error": "Invalid email format."}, status=status.HTTP_400_BAD_REQUEST)
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
                return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"error": f"Failed to send OTP email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ObjectDoesNotExist:
            # Handle database related issues, if any
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"error": "Unable to process the OTP request. Please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            # Handle any unexpected errors
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def is_valid_email(self, email):
        # Basic check for email format
        return "@" in email and "." in email


# Verify OTP and create user
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        email = request.data.get('email')
        otp_code = request.data.get('otp_code')

        # Check if email, OTP, password, and confirm_password are provided
        if not email or not otp_code:
            return Response({"status":status.HTTP_400_BAD_REQUEST,"error": "Email, OTP are required."}) 

        try:
            # Retrieve OTP from the database
            otp = OTP.objects.filter(email=email, otp_code=otp_code, expired_at__gt=timezone.now()).first()

            # Check if OTP is valid and not expired
            if not otp:
                return Response({"status":status.HTTP_400_BAD_REQUEST,"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)
            password = request.data.get('password')
            confirm_password = request.data.get('confirm_password')
            if not password or not confirm_password:
                return Response({
                    "status": status.HTTP_200_OK,
                    "message": "OTP verified successfully. Now provide a password to complete registration."
                }, status=status.HTTP_200_OK)
            # Check if passwords match
            if password != confirm_password:
                return Response({"status":status.HTTP_400_BAD_REQUEST,"error": "Passwords do not match."})

            # Create the user with the provided email and password
            user = User.objects.create_user(email=email, password=password, username=email)

            # Delete the OTP record after successful registration
            otp.delete()
            user_serializer = UserRegistrationSerializer(user)
            return Response({
                "status": status.HTTP_201_CREATED,
                "message": "User registered successfully.",
                "user": user_serializer.data  # Include the serialized user data in the response
            }, status=status.HTTP_201_CREATED)

        except IntegrityError as e:
            # Handle duplicate username error
            if "unique constraint" in str(e).lower():
                return Response({"status":status.HTTP_400_BAD_REQUEST,"error": "A user with this email already exists. Please use a different email."}, 
                                status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"status":status.HTTP_400_BAD_REQUEST,"error": f"An unexpected database error occurred: {str(e)}"}, 
                                 status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            # Handle other unexpected errors
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self,request):
        email = request.data.get('email')
        password = request.data.get('password')
        if not email:
            return Response({"status":status.HTTP_400_BAD_REQUEST,"error": "Email are required."}, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({"status":status.HTTP_400_BAD_REQUEST,"error": "password are required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = authenticate(request,username=email,password=password)
            if user is None:
                return Response({"status":status.HTTP_401_UNAUTHORIZED,"error": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)
            if not user.check_password(password):
                return Response({"status":status.HTTP_401_UNAUTHORIZED,"error": "Invalid password."}, status=status.HTTP_401_UNAUTHORIZED)
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
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#Forgot Password API
class ForgotPasswordView(APIView):

    def post(self, request):
        try:
            email = request.data.get("email")
            if not email:
                return Response({"status": status.HTTP_400_BAD_REQUEST, "error": "Email is required"}, 
                                status=status.HTTP_400_BAD_REQUEST)

            # Check if user exists
            user = User.objects.filter(email=email).first()
            if not user:
                return Response({"status": status.HTTP_400_BAD_REQUEST, "error": "User with this email does not exist."}, 
                                status=status.HTTP_400_BAD_REQUEST)

            # Generate a 4-digit OTP
            otp_code = ''.join(random.choices(string.digits, k=4))
            expiration_time = timezone.now() + timezone.timedelta(seconds=60)

            # Delete any existing OTP for the user
            OTP.objects.filter(email=email).delete()

            # Save new OTP in the database
            OTP.objects.create(email=email, otp_code=otp_code, expired_at=expiration_time)

            # # Send OTP via email
            # subject = "Password Reset OTP"
            # message = f"Your OTP for password reset is: {otp_code}. It is valid for 60 seconds."
            # send_mail(subject, message, settings.EMAIL_HOST_USER, [email])

            return Response({
                "status": status.HTTP_200_OK,
                "message": "OTP sent successfully to your email.",
                "otp": otp_code  # ✅ OTP included in response for testing purposes
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "error": f"Failed to send OTP email: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPAndResetPasswordView(APIView): 

    def post(self, request):
        try:
            email = request.data.get("email")
            otp_code = request.data.get("otp_code")

            # ✅ Step 1: Check if email and OTP are provided
            if not email or not otp_code:
                return Response({"status": status.HTTP_400_BAD_REQUEST, "error": "Email and OTP are required."}, 
                                status=status.HTTP_400_BAD_REQUEST)

            # ✅ Step 2: Check if OTP is valid and not expired
            otp = OTP.objects.filter(email=email, otp_code=otp_code, expired_at__gt=timezone.now()).first()
            if not otp:
                return Response({"status": status.HTTP_400_BAD_REQUEST, "error": "Invalid or expired OTP."}, 
                                status=status.HTTP_400_BAD_REQUEST)
                
            password = request.data.get("password")
            confirm_password = request.data.get("confirm_password")
            if not password or not confirm_password:
                    return Response({
                        "status": status.HTTP_200_OK,
                        "message": "OTP verified successfully. Now provide password and confirm password."
                    }, status=status.HTTP_200_OK)
            if password != confirm_password:
                return Response({"status": status.HTTP_400_BAD_REQUEST, "error": "Passwords do not match."}, 
                                status=status.HTTP_400_BAD_REQUEST)

            # ✅ Step 4: Update user's password
            user = User.objects.filter(email=email).first()
            if not user:
                return Response({"status": status.HTTP_404_NOT_FOUND, "error": "User not found."}, 
                                status=status.HTTP_404_NOT_FOUND)

            user.password = make_password(password)  # Hash the password before saving
            user.save()

            # ✅ Step 5: Delete the OTP after successful password reset
            otp.delete()

            return Response({
                "status": status.HTTP_200_OK,
                "message": "Password reset successfully."
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"error":str(e)})
        

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
                return Response({"status":status.HTTP_400_BAD_REQUEST,"error":"Name is Requried"},status.HTTP_400_BAD_REQUEST)
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