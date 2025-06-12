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

                    We received your request for a single-use code to reset the password for your email account.

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
                return Response({"status": status.HTTP_401_UNAUTHORIZED, "message": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)

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
            
