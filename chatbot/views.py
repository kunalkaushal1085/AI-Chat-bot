from django.shortcuts import render,redirect
from django.contrib.auth import get_user_model
from  rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework import status
from django.contrib.auth import authenticate,login as django_login, logout as django_logout
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from rest_framework.authtoken.models import Token
from .models import *
from .serializers import UserRegistrationSerializer
from dotenv import load_dotenv
import re
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.permissions import AllowAny
from django.utils import timezone
from django.contrib.auth.hashers import make_password
import random
from datetime import timedelta
from rest_framework.decorators import action
import os
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
import string
from .serializers import *
from django.core.files.base import ContentFile
import json
import logging
import base64
import requests
from django.http import JsonResponse
from chatbot.models import LoginAttempt
from chatbot.helper import upload_image_to_s3
from django.contrib.sessions.backends.db import SessionStore
from utils.base import get_user_from_token
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
import tweepy
import secrets
import hashlib
from urllib.parse import urlencode



logger = logging.getLogger(__name__)

load_dotenv()



def baseurl(request):
    """
    Return a BASE_URL template context for the current request.
    """
    if request.is_secure():
        scheme = "https://"
    else:
        scheme = "http://"

    return scheme + request.get_host()
    

def convertclientidsecret(client_id, client_secret):
    
    # Concatenate client_id and client_secret with a colon
    client_credentials = f"{client_id}:{client_secret}"
    # Base64 encode the client credentials
    encoded_credentials = base64.b64encode(client_credentials.encode('utf-8')).decode('utf-8')

    return encoded_credentials

#Global var
AUTHCODE =''

# Generate OTP and send it via email
class GenerateOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not self.is_valid_email(email):
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Invalid email format."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            if User.objects.filter(email=email).exists():
                return Response({"status":status.HTTP_200_OK,"message":"user already exists"},status.HTTP_200_OK)
            otp = OTP.objects.filter(email=email).first()
            
            if otp:
                # Check if OTP has expired (after 60 seconds)
                if otp.expired_at < timezone.now():
                    # Reset is_verified to False if expired
                    otp.is_verified = False
                    otp.save()
                elif otp.expired_at > timezone.now():
                    return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "OTP already sent. Please check your email."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate a new OTP code if no valid OTP exists or the previous one expired
            otp_code = str(random.randint(1000, 9999))
            expiration_time = timezone.now() + timedelta(seconds=60)
            
            if otp:
                # Update existing OTP record
                otp.otp_code = otp_code
                otp.expired_at = expiration_time
                otp.is_verified = False  # Reset the verification status to False
                otp.save()
            else:
                # Create new OTP record if none exists
                otp = OTP.objects.create(email=email, otp_code=otp_code, expired_at=expiration_time, is_verified=False)
            
            try:
                # Send OTP via email (this part is currently commented out)
                message = f"""
                    Hi {email},

                    We received your request for a single-use code to set up your account.

                    Your Single-use code is: {otp_code}

                    Enter this code on the official app. Don't share it with anyone.

                    Thanks,  
                    Sussima-bot team
                    """
                # send_mail(
                #     "Your OTP Code",
                #     f"Your OTP code is: {otp_code}",
                #     settings.EMAIL_HOST_USER,
                #     [email],
                #     fail_silently=False,
                # )
                send_mail(
                    subject="Your OTP Code{otp_code}",
                    message=message,
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[email],
                    fail_silently=False,
                )

                return Response({"status": status.HTTP_200_OK, "message": "OTP sent to your email.", "otp": otp_code}, status=status.HTTP_200_OK)

            except Exception as e:
                return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": f"Failed to send OTP email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except ObjectDoesNotExist:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": "Unable to process the OTP request. Please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def is_valid_email(self, email):
        return "@" in email and "." in email



User = get_user_model()
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp_code = request.data.get('otp_code')
        
        if not email:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get the latest OTP for the user that is not yet verified
            otp_instance = OTP.objects.filter(email=email, otp_code=otp_code).latest('created_at')

            if not otp_instance:
                return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if OTP has expired
            current_time = timezone.now()
            if current_time > otp_instance.expired_at:
                otp_instance.is_verified = True  # Mark expired OTP as verified
                otp_instance.save()
                return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "OTP has expired. Please request a new OTP."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if OTP is already verified
            if otp_instance.is_verified:
                return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "OTP has already been verified."}, status=status.HTTP_400_BAD_REQUEST)

            # Mark OTP as verified and save
            otp_instance.is_verified = True
            otp_instance.save()

            return Response({"status": status.HTTP_200_OK, "message": "OTP verified successfully."}, status=status.HTTP_200_OK)

        except OTP.DoesNotExist:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": f"Invalid or expired OTP. {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)


# Create user
class RegisterUserView(APIView):
    def post(self, request):
        try:
            serializer = UserRegistrationSerializer(data=request.data)
            if not request.data.get('email'):
                return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Email is required."}, status=400)

            if not request.data.get('password'):
                return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Password is required."}, status=400)

            email = request.data['email']
            if not OTP.objects.filter(email=email, is_verified=True).exists():
                return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "OTP not verified for this email."}, status=400)

            if User.objects.filter(email=email).exists():
                return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Email is already registered."}, status=400)

            if serializer.is_valid():
                serializer.save()
                return Response({"status": status.HTTP_200_OK, "message": "User registered successfully.","data":serializer.data}, status=200)
            else:
                return Response({"status": status.HTTP_400_BAD_REQUEST, "errors": serializer.errors}, status=400)

        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": str(e)}, status=500)
        

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
            expiration_time = timezone.now() + timezone.timedelta(minutes=5)

            # Delete any existing OTP for the user
            OTP.objects.filter(email=email).delete()

            # Save new OTP in the database
            OTP.objects.create(email=email, otp_code=otp_code, expired_at=expiration_time)

            # # Send OTP via email
            subject = "Password Reset OTP"
            message = f"Your OTP for password reset is: {otp_code}. It is valid for 5 minutes."
            send_mail(subject, message, settings.EMAIL_HOST_USER, [email])

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
            
from rest_framework_simplejwt.tokens import RefreshToken
#User Login 
class LoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Password is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Get or create LoginAttempt record
        attempt, _ = LoginAttempt.objects.get_or_create(email=email)

        # Check if the email is locked
        if attempt.is_locked():
            remaining = (attempt.locked_until - timezone.now()).seconds
            return Response({
                "status": status.HTTP_403_FORBIDDEN,
                "message": f"Account locked due to multiple failed attempts. Try again in {remaining} seconds."
            }, status=status.HTTP_403_FORBIDDEN)

        try:
            user = authenticate(request, username=email, password=password)

            if user is None or not user.check_password(password):
                # Failed attempt
                attempt.failed_attempts += 1

                if attempt.failed_attempts >= 5:
                    attempt.locked_until = timezone.now() + timedelta(minutes=1)
                    attempt.save()
                    return Response({
                        "status": status.HTTP_403_FORBIDDEN,
                        "message": "Too many failed attempts. Account locked for 1 minute."
                    }, status=status.HTTP_403_FORBIDDEN)

                attempt.save()
                return Response({"status": status.HTTP_401_UNAUTHORIZED, "message": "Please try again or click forgot password to reset it."}, status=status.HTTP_401_UNAUTHORIZED)

            # Success: reset attempts
            attempt.failed_attempts = 0
            attempt.locked_until = None
            attempt.save()

            django_login(request, user)
            refresh = RefreshToken.for_user(user)
            access = refresh.access_token

            return Response({
                "status": status.HTTP_200_OK,
                "message": "Login successful.",
                "access": str(access),
                "refresh": str(refresh),
                "base_url": baseurl(request)
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": f"An unexpected error occurred: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#Refresh to access token generate API
class CustomTokenRefreshView(APIView):
    def post(self, request, *args, **kwargs):
        
        refresh_token = request.headers.get('Refresh-Token')
        if not refresh_token:
            return Response({'detail': 'Refresh token missing in headers.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = RefreshToken(refresh_token)
            access_token = str(token.access_token)
            return Response({'status':status.HTTP_200_OK,'access': access_token,'refresh': str(token)}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'detail': 'Invalid or expired refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)


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
class UserUpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self,request):
        try:
            user = request.user
            if not user or not user.is_authenticated:
                user = get_user_from_token(request)
                print(user,'user')
                if not user:
                    return Response({"status": 401, "message": "Invalid or expired token."}, status=401)
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
            user.first_name = name
            user.save()
            message = "Profile created successfully." if created else "Profile updated successfully."
            return Response(
                {"status":status.HTTP_200_OK,"message": message, "profile": UserProfileSerializer(profile).data},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"message":str(e)})


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if not user or not user.is_authenticated:
            return Response({"status": 401, "message": "Invalid or expired token."}, status=401)
        try:
            profile = UserProfile.objects.get(user=user)
            serializer = UserProfileSerializer(profile)
            return Response({"status": status.HTTP_200_OK, "profile": serializer.data}, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response({"status": status.HTTP_404_NOT_FOUND, "message": "Profile not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#Create a WorkSpace
class WorkSpaceView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        user = request.user
        if not user or not user.is_authenticated:
            user = get_user_from_token(request)
            print(user,'user')
            if not user:
                return Response({"status": 401, "message": "Invalid or expired token."}, status=401)
        name = request.data.get("name")
        description = request.data.get("description")
        image = request.FILES.get("image")
        logger.debug(f"Received data: name={name}, description={description}")
        if not name:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Workspace name is required."}, status=status.HTTP_400_BAD_REQUEST)
        if description is None:
            description =""
        
        try:
            workspace = WorkSpace.objects.create(
                user=user,
                name=name,
                description=description,
                image=image if image else None  # Set image if provided
            )
            serializer = WorkSpaceSerializer(workspace)
            workspace_data = serializer.data
            if workspace.image:
                workspace_data['image'] = request.build_absolute_uri(workspace.image.url)
                
            logger.debug(f"Workspace created: {workspace_data}")

            return Response({
                "status": status.HTTP_200_OK,
                "message": "Workspace created successfully.",
                "workspace": workspace_data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error occurred: {str(e)}")
            return Response({
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": f"An unexpected error occurred: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#Get user specific workspace
class UserWorkSpaceListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        try:
            user = request.user
            if not user or not user.is_authenticated:
                user = get_user_from_token(request)
                print(user,'user')
                if not user:
                    return Response({"status": 401, "message": "Invalid or expired token."}, status=401)
            workspaces = WorkSpace.objects.filter(user=user)
            serializer = WorkSpaceSerializer(workspaces, many=True)
            active_workspace_id = request.session.get('active_workspace_id')
            response_data = {
                "status": status.HTTP_200_OK,
                "user_id": user.id,
                "username": user.username,
                "active_workspace_id": active_workspace_id,
                "workspaces": serializer.data
            }
            return Response(response_data)
        except Exception as e:
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"message":str(e)})

    @action(detail=True, methods=['delete'])
    def delete(self, request, workspace_id=None):
        try:
            user = request.user
            workspace = WorkSpace.objects.filter(id=workspace_id, user=user).first()

            if not workspace:
                return Response({
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Workspace not found or you do not have permission to delete it."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Delete the workspace
            workspace.delete()

            return Response({
                "status": status.HTTP_200_OK,
                "message": "Workspace deleted successfully."
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    @action(detail=True, methods=['put'])
    def put(self,request,workspace_id):
        user = request.user
        name = request.data.get("name")
        description = request.data.get("description")  
        image = request.FILES.get("image") 
        image_url = request.data.get("image")
        if not name:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Workspace name is required."}, status=status.HTTP_400_BAD_REQUEST)

        workspace = WorkSpace.objects.filter(id=workspace_id, user=user).first()
        if not workspace:
            return Response({
                "status": status.HTTP_404_NOT_FOUND,
                "message": "Workspace not found or you do not have permission to update it."
            }, status=status.HTTP_404_NOT_FOUND)
        if description is None:
            description=""
        try:
            if image:
                workspace.image = image 
             # If image is passed explicitly as null or empty string, clear the image
            elif image_url in [None, '', 'null']:
                workspace.image = None
            # Handle the case when an image URL is provided
            elif image_url and self.is_valid_url(image_url): 
                workspace.image = self.handle_image_url(image_url)
            if name:
                workspace.name = name
            if description:
                    workspace.description = description

            workspace.save()
            serializer = WorkSpaceSerializer(workspace)
            workspace_data = serializer.data

            # Include the full image URL if the workspace has an image
            if workspace.image:
                workspace_data['image'] = request.build_absolute_uri(workspace.image.url)
            else:
                print('inside else')
                workspace_data['image'] = None
            logger.debug(f"Workspace updated: {workspace_data}")

            return Response({
                "status": status.HTTP_200_OK,
                "message": "Workspace updated successfully.",
                "workspace": workspace_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error occurred: {str(e)}")
            return Response({
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": f"An unexpected error occurred: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    def is_valid_url(self, url):
        """
        Checks if the provided URL is valid.
        """
        regex = re.compile(
            r'^(?:http|ftp)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
            r'localhost|' # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
            r'(?::\d+)?' # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return re.match(regex, url) is not None

    def handle_image_url(self, image_url):
        """
        Downloads the image from the provided URL and returns it as a file.
        """
        try:
            # Fetch the image from the URL
            response = requests.get(image_url)
            response.raise_for_status()  # Raise error if status code isn't 200
            
            # Get image content and file name
            image_content = response.content
            image_name = image_url.split("/")[-1]

            # Save the image as a file
            image_file = ContentFile(image_content, name=image_name)
            return image_file
        except requests.exceptions.RequestException as e:
            logger.error(f"Error downloading image from URL: {str(e)}")
            return None


#Actie Workspace
class SetActiveWorkspaceView(APIView):
    permission_classes = [IsAuthenticated]
    """We have store the Active workspace in session!. """
    def post(self,request):
        user = request.user
        if not user or not user.is_authenticated:
            user = get_user_from_token(request)
            if not user:
                return Response({"status": 401, "message": "Invalid or expired token."}, status=401)
        workspace_id = request.data.get("workspace_id")
        if not workspace_id:
            return Response({
                "status": status.HTTP_400_BAD_REQUEST,
                "message": "Workspace ID is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        try:
            workspace = WorkSpace.objects.get(id=workspace_id,user=user)
        except WorkSpace.DoesNotExist:
            return Response({"status": status.HTTP_404_NOT_FOUND,
                "message": "Workspace not found or access denied."},status=status.HTTP_404_NOT_FOUND)
        # Store active workspace in session
        request.session['active_workspace_id']=workspace_id
        request.session.modified = True
        return Response({
            "status": status.HTTP_200_OK,
            "message": "Workspace set as active.",
            "active_workspace_id": workspace_id
        }, status=status.HTTP_200_OK)
        
        
#Convert clientID and Client Secret in Base64
def convertclientidsecret(client_id, client_secret):
    try:
        # Concatenate client_id and client_secret with a colon
        client_credentials = f"{client_id}:{client_secret}"
        # Base64 encode the client credentials
        encoded_credentials = base64.b64encode(client_credentials.encode('utf-8')).decode('utf-8')

        return encoded_credentials
    except Exception as e:
        return Response({"status":status.HTTP_400_BAD_REQUEST,"message":str(e)})


class GetAuthorizationUrl(APIView):
    def get(self, request):
        try:
            state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            auth_url = (
                f"{os.getenv('AUTH_URL')}?"
                f"response_type=code&"
                f"client_id={os.getenv('CLIENT_ID')}&"
                f"redirect_uri={os.getenv('REDIRECT_URI')}&"
                f"state={state}&"
                f"scope=openid%20profile%20w_member_social%20email"
            ) 

            return Response({"status": status.HTTP_200_OK,"message":"success", "auth_url": auth_url})
        except Exception as e:
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"message":str(e)})
        
        
class LinkedInRedirectView(APIView):
    def get(self, request):
        # Step 3: Handle the redirect and extract the code from the URL
        auth_code = request.GET.get('code')
        if auth_code:
    
            # Step 4: Exchange the authorization code for an access token
            token_url = os.getenv("TOKEN_URL")
            payload = {
                'grant_type': 'authorization_code',
                'code': auth_code,
                'redirect_uri': os.getenv('REDIRECT_URI'),
                'client_id': os.getenv('CLIENT_ID'),
                'client_secret': os.getenv('CLIENT_SECRET'),
            }

            response = requests.post(token_url, data=payload)

            if response.status_code == 200:
                # Successfully got the access token
                token_data = response.json()
                access_token = token_data.get('access_token')
                expires_in = token_data.get('expires_in')
                scope = token_data.get('scope')
                token_type = token_data.get('token_type')
                id_token = token_data.get('id_token')

                return Response({"status":status.HTTP_200_OK,
                    "message":"success",
                    "access_token":access_token,
                    "expires_in":expires_in,
                    "scope":scope,
                    "token_type":token_type,
                    "id_token":id_token
                })
            else:
                return Response({"status":status.HTTP_400_BAD_REQUEST, "message": "Failed to get access token"}, status=response.status_code)
        
        else:
            return Response({"status":status.HTTP_400_BAD_REQUEST, "message": "Authorization code not found"}, status=400)
        
        
#Get UserInfo
class GetUserInfo(APIView):
    def get(self,request):
        try:
            url = "https://api.linkedin.com/v2/me"
            access_token = "AQW2cX3mNyd2-4hvW69Nlmtpm7iq-k1JtdO8fJoMEGjr8QIKgQPualqNMZ5ojOz9u61L9jE3u3xAL2hu9IJMhXMGzfDIijekLre6wrL-ln2HO3iUUCb_EflJJq-NBk7vFdHLDUJ0KBDq1YsgwYZM4bu-dE-TW9JlqE6guTUwKqe_NE7hv0WSOep8P1N4rwIT-JaoT4MuKu_YT-3p7kM6j5WLr2lg-oiEEwDEZzr8QkZdrBvm-czJYJJlgoeIKrDCb_fDsZu1ZQ04eKyg7u_mlJGWfIEDdAkXoKpjN3uHW7xYh24EyZJzaps1PV2Fl2H1991utS4Wb-LXKZBpgxrcGzNi1tMX1A"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "X-Restli-Protocol-Version": "2.0.0"
                }
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": "Failed to fetch user info", "details": response.json()}

        except Exception as e:
            print(e)
            


facebook_auth_code = None

class FacebookCallbackView(APIView):
    def get(self, request):
        user_id = request.GET.get('state')
        print(f"{user=}")
        auth_code = request.GET.get('code')
        if not auth_code:
            # Redirect user to Facebook Login
            state = "somerandomstate"
            print(f"{os.getenv("REDIRECT_URL")=}")
            auth_url = (
                f"https://www.facebook.com/v19.0/dialog/oauth?"
                f"response_type=code&"
                f"client_id={os.getenv("FACEBOOK_APP_ID")}&"
                f"redirect_uri={os.getenv("REDIRECT_URL")}&"
                f"state={user}&"
                f"scope=pages_manage_posts,pages_read_engagement,pages_show_list,instagram_basic,instagram_content_publish,email"
                
            )
            return redirect(auth_url)

        # Step 1: Exchange code for short-lived token
        token_url = "https://graph.facebook.com/v19.0/oauth/access_token"
        token_params = {
            "client_id": os.getenv("FACEBOOK_APP_ID"),
            "redirect_uri": os.getenv("REDIRECT_URL"),
            "client_secret": os.getenv("FACEBOOK_APP_SECRET"),
            "code": auth_code
        }
        token_response = requests.get(token_url, params=token_params)
        if token_response.status_code != 200:
            return Response({
                "error": "Failed to exchange code for short-lived token",
                "details": token_response.json()
            }, status=status.HTTP_400_BAD_REQUEST)
        user_access_token = token_response.json().get("access_token")
        if not user_access_token:
            return Response({"error": "No access token returned from Facebook."}, status=status.HTTP_400_BAD_REQUEST)

        # Step 2: Exchange short-lived token for long-lived token
        long_token_url = "https://graph.facebook.com/v19.0/oauth/access_token"
        long_token_params = {
            "grant_type": "fb_exchange_token",
            "client_id": os.getenv("FACEBOOK_APP_ID"),
            "client_secret": os.getenv("FACEBOOK_APP_SECRET"),
            "fb_exchange_token": user_access_token
        }
        long_token_response = requests.get(long_token_url, params=long_token_params)
        if long_token_response.status_code != 200:
            return Response({
                "error": "Failed to exchange for long-lived token",
                "details": long_token_response.json()
            }, status=status.HTTP_400_BAD_REQUEST)
        long_lived_token = long_token_response.json().get("access_token")
        if not long_lived_token:
            return Response({"error": "No long-lived token returned from Facebook."}, status=status.HTTP_400_BAD_REQUEST)
        user_info_url = "https://graph.facebook.com/me"
        params = {
            "fields": "id,name,email",
            "access_token": long_lived_token
        }
        user_info_response = requests.get(user_info_url, params=params)
        user_info = user_info_response.json()
        facebook_user_id = user_info.get("id")
        facebook_email = user_info.get("email")

        expires_at = timezone.now() + timedelta(days=60)
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        SocialToken.objects.update_or_create(
            user=user,
            provider='facebook',
            social_user_id=facebook_user_id,
            defaults={
                'access_token': long_lived_token,
                'expires_at': expires_at
            }
        )
        # Return only the long-lived user access token valid for 60days
        return Response({
            "user_access_token": long_lived_token
        }, status=status.HTTP_200_OK) 

# class GetDecryptedTokenView(APIView):
#     def post(self, request):
#         # provider = request.data.get('provider')
#         # social_user_id = request.data.get('social_user_id')
#         # if not provider or not social_user_id:
#         #     return Response({'error': 'provider and social_user_id are required.'}, status=status.HTTP_400_BAD_REQUEST)
#         try:
#             token_obj = SocialToken.objects.get(provider=provider, social_user_id=social_user_id)
#             return Response({
#                 'provider': provider,
#                 'social_user_id': social_user_id,
#                 'access_token': token_obj.access_token
#             }, status=status.HTTP_200_OK)
#         except SocialToken.DoesNotExist:
#             return Response({'error': 'Token not found.'}, status=status.HTTP_404_NOT_FOUND) 

def get_pages_info(user_access_token):
    """
    Fetch the list of pages the user manages using the user access token.
    """
    try:
        url = "https://graph.facebook.com/v19.0/me/accounts"
        resp = requests.get(url, params={"access_token": user_access_token})
        print(resp.json(),'resp')
        return resp.json()
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class FacebookPagesView(APIView):
    def post(self, request):
        user_access_token = request.data.get("user_access_token")
        if not user_access_token:
            return Response({"error": "user_access_token is required"}, status=status.HTTP_400_BAD_REQUEST)
        pages_info = get_pages_info(user_access_token)
        return Response(pages_info, status=status.HTTP_200_OK) 


# class FacebookSendPostView(APIView):
#     def post(self, request):
#         try:
#             page_id = request.data.get("page_id")
#             page_access_token = request.data.get("page_access_token")
#             message = request.data.get("message")
#             if not all([page_id, page_access_token, message]):
#                 return Response({"error": "page_id, page_access_token, and message are required"}, status=status.HTTP_400_BAD_REQUEST)
#             post_url = f"https://graph.facebook.com/v19.0/{page_id}/feed"
#             post_data = {
#                 "message": message,
#                 "access_token": page_access_token
#             }
#             response = requests.post(post_url, data=post_data)
#             try:
#                 resp_json = response.json()
#             except Exception:
#                 resp_json = {"error": "Invalid response from Facebook."}
#             if response.status_code != 200:
#                 return Response({"error": "Failed to post to Facebook", "details": resp_json}, status=response.status_code)
#             return Response(resp_json, status=status.HTTP_200_OK) 
#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SocialPostView(APIView):
    def post(self, request):
        # Common params
        message = request.data.get("message")
        post_to_facebook = request.data.get("post_to_facebook", False)
        post_to_instagram = request.data.get("post_to_instagram", False)
        page_id = request.data.get("page_id")
        page_access_token = request.data.get("page_access_token")
        image_url = request.data.get("image_url")  # For Instagram

        results = {}

        if post_to_facebook:
            # Post to Facebook Page
            fb_url = f"https://graph.facebook.com/v19.0/{page_id}/feed"
            fb_data = {"message": message, "access_token": page_access_token}
            fb_resp = requests.post(fb_url, data=fb_data)
            results["facebook"] = fb_resp.json()

        if post_to_instagram:
            # 1. Get IG user ID from Page
            ig_url = f"https://graph.facebook.com/v19.0/{page_id}?fields=instagram_business_account&access_token={page_access_token}"
            ig_resp = requests.get(ig_url)
            ig_user_id = ig_resp.json().get("instagram_business_account", {}).get("id")
            if not ig_user_id:
                results["instagram"] = {"error": "No Instagram business account linked to this page."}
            else:
                # 2. Create media object
                media_url = f"https://graph.facebook.com/v19.0/{ig_user_id}/media"
                media_data = {"image_url": image_url, "caption": message, "access_token": page_access_token}
                media_resp = requests.post(media_url, data=media_data)
                creation_id = media_resp.json().get("id")
                if not creation_id:
                    results["instagram"] = {"error": "Failed to create media object.", "details": media_resp.json()}
                else:
                    # 3. Publish media
                    publish_url = f"https://graph.facebook.com/v19.0/{ig_user_id}/media_publish"
                    publish_data = {"creation_id": creation_id, "access_token": page_access_token}
                    publish_resp = requests.post(publish_url, data=publish_data)
                    results["instagram"] = publish_resp.json()

        return Response(results)



#Convert Clientid and secret in Base64
def convert_client_id_secret(client_id: str, client_secret: str) -> str:
    client_credentials = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(client_credentials.encode('utf-8')).decode('utf-8')
    return encoded_credentials


# Generate a random state value
def generate_state() -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))



# LinkedIn app credentials
client_id = "7701uyxp84acx3"
client_secret = "WPL_AP1.iZI9aqbm1lFzADAr.glkP2Q=="
# redirect_url="https://www.linkedin.com/developers/tools/oauth/redirect"

# LinkedIn URLs
auth_url = "https://www.linkedin.com/oauth/v2/authorization"
token_url = "https://www.linkedin.com/oauth/v2/accessToken"

# Must match the redirect URI you set in your LinkedIn app
redirect_uri = "http://localhost:8000/api/oauth/login"

linkedin_code =""

from urllib.parse import quote
def generate_state():
    # Implement your state generation logic here
    import uuid
    return str(uuid.uuid4())


class LinkedInOAuthLoginView(APIView):
    def get(self, request):
        code = request.GET.get("code")
        state = request.GET.get("state")
        if not code:
            # Step 1: Redirect user to LinkedIn auth page
            state_val = generate_state()
            # scope = "openid profile email w_member_social"
            scope = "r_liteprofile w_member_social"
            authorization_url = (
                f"https://www.linkedin.com/oauth/v2/authorization"
                f"?response_type=code&client_id={client_id}"
                f"&redirect_uri={redirect_uri}&state={state_val}"
                f"&scope={quote(scope)}"
            )
            return redirect(authorization_url)

        # Step 2: User came back with 'code', so exchange for access token
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'client_secret': client_secret
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post(token_url, data=data, headers=headers)
        token_data = response.json()
        print(token_data, "token")

        if response.status_code != 200:
            return Response({"error": "Failed to get access token", "details": token_data}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Save token in the database
            access_token = token_data.get("access_token")
            expires_in = token_data.get("expires_in")
            expires_at = timezone.now() + timedelta(seconds=expires_in) if expires_in else None
            # You can add logic to associate with a user if needed
            LinkedinToken.objects.create(
                access_token=access_token,
                expires_at=expires_at
            )
        except Exception as e:
            return Response({"error": "Error saving token", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(token_data, status=status.HTTP_200_OK) 
    


class LinkedInRefreshTokenView(APIView):
    def post(self, request):
        refresh_token = request.data.get("refresh_token")
        if not refresh_token:
            return Response({"error": "refresh_token is required"}, status=status.HTTP_400_BAD_REQUEST)
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': client_id,
            'client_secret': client_secret
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.post(token_url, data=data, headers=headers)
        token_data = response.json()
        if response.status_code != 200:
            return Response({"error": "Failed to refresh token", "details": token_data}, status=status.HTTP_400_BAD_REQUEST)
        return Response(token_data, status=status.HTTP_200_OK)


class LinkedInPostView(APIView):
    def post(self, request):
        content = request.data.get("content")
        if not content:
            return Response({"error": "Content is required"}, status=status.HTTP_400_BAD_REQUEST)
        #Get the latest token
        token_obj = LinkedinToken.objects.order_by('-created_at').first()
        if not token_obj:
            return Response({"error": "No valid token found"}, status=status.HTTP_400_BAD_REQUEST)
        access_token = token_obj.access_token
        print(access_token,'access')
        # Get the LinkedIn user ID (urn)
        profile_url = "https://api.linkedin.com/v2/me"
        headers = {"Authorization": f"Bearer {access_token}"}
        profile_resp = requests.get(profile_url, headers=headers)
        if profile_resp.status_code != 200:
            return Response({'error': 'Failed to fetch LinkedIn profile'}, status=profile_resp.status_code)
        user_urn = profile_resp.json().get("id")
        if not user_urn:
            return Response({'error': 'Could not get user ID from LinkedIn'}, status=400)
        # Prepare the post payload
        post_url = "https://api.linkedin.com/v2/ugcPosts"
        post_data = {
            "author": f"urn:li:person:{user_urn}",
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {
                        "text": content
                    },
                    "shareMediaCategory": "NONE"
                }
            },
            "visibility": {
                "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
            }
        }
        post_resp = requests.post(post_url, headers={
            "Authorization": f"Bearer {access_token}",
            "X-Restli-Protocol-Version": "2.0.0",
            "Content-Type": "application/json"
        }, json=post_data)

        if post_resp.status_code not in [200, 201]:
            return Response({'error': 'Failed to post to LinkedIn', 'details': post_resp.json()}, status=post_resp.status_code)

        return Response({'message': 'Post successful', 'linkedin_response': post_resp.json()})


CODE_VERIFIER_STORE = {}

def generate_pkce():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    return verifier, challenge

class TwitterCallbackView(APIView):
    def get(self, request):
        auth_code = request.GET.get("code")
        if not auth_code:
            code_verifier, code_challenge = generate_pkce()
            CODE_VERIFIER_STORE["latest"] = code_verifier
            state = secrets.token_urlsafe(16)
            client_id = os.getenv("TWITTER_CLIENT_ID")
            callback_url = os.getenv("TWITTER_CALLBACK_URL")
            auth_url = "https://twitter.com/i/oauth2/authorize?" + urlencode({
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": callback_url,
                "scope": "tweet.read users.read offline.access",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256"
            })
            return redirect(auth_url)

        token_url = "https://api.twitter.com/2/oauth2/token"
        code_verifier = CODE_VERIFIER_STORE.get("latest")
        client_id = os.getenv("TWITTER_CLIENT_ID")
        client_secret = os.getenv("TWITTER_CLIENT_SECRET")
        callback_url = os.getenv("TWITTER_CALLBACK_URL")

        data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": callback_url,
            "code_verifier": code_verifier
        }

        # Add HTTP Basic Auth header
        basic_auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {basic_auth}"
        }

        response = requests.post(token_url, data=urlencode(data), headers=headers)

        if response.status_code != 200:
            return Response({
                "error": "Token exchange failed",
                "details": response.json()
            }, status=response.status_code)

        token_data = response.json()
        expires_at = timezone.now() + timedelta(days=60)
        SocialToken.objects.update_or_create(
            provider='twitter',
            defaults={
                'access_token': token_data.get("access_token"),
                'refresh_token': token_data.get("refresh_token"),
                'expires_at': expires_at
            }
        )
        return Response({
            "access_token": token_data.get("access_token"),
            "refresh_token": token_data.get("refresh_token"),
            "expires_in": token_data.get("expires_in"),
            "scope": token_data.get("scope")
        }, status=200)


#Send Twitter Tweet api
class TwitterPostTweetView(APIView):
    def post(self, request):
        
        tweet_text = request.data.get("tweet")
        if not tweet_text:
            return Response({"error": "Tweet text is required."}, status=status.HTTP_400_BAD_REQUEST)
        client = tweepy.Client(
            bearer_token=os.getenv('TWITTER_BEARER_TOKEN'),
            consumer_key=os.getenv('TWITTER_API_KEY'),
            consumer_secret=os.getenv('TWITTER_API_SECRET'),
            access_token=os.getenv('TWITTER_ACCESS_TOKEN'),
            access_token_secret=os.getenv('TWITTER_ACCESS_TOKEN_SECRET')
        )
        try:
            tweet = client.create_tweet(text=tweet_text)
            tweet_id = tweet.data["id"]
            return Response({"message": "Tweet posted successfully!", "tweet_id": tweet_id}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
