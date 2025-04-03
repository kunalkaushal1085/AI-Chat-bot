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
import json
import logging
import base64
import requests
from django.http import JsonResponse

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
                send_mail(
                    "Your OTP Code",
                    f"Your OTP code is: {otp_code}",
                    settings.EMAIL_HOST_USER,
                    [email],
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
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "OTP not found for this email."}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": f"Invalid or expired OTP. {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)


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
            subject = "Password Reset OTP"
            message = f"Your OTP for password reset is: {otp_code}. It is valid for 60 seconds."
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
            django_login(request, user)

            # If user is found, create a token (or get existing one)
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                "status": status.HTTP_200_OK,
                "message": "Login successful.",
                "token": token.key,
                "base_url":baseurl(request)
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
        name = request.data.get("name")
        description = request.data.get("description")
        logger.debug(f"Received data: name={name}, description={description}")
        if not name:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Workspace name is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not description:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Workspace description is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Create a new workspace for the logged-in user
            workspace = WorkSpace.objects.create(
                user=user,
                name=name,
                description=description
            )
            logger.debug(f"Workspace created: {workspace}")
            logger.debug(f"Workspace type: {type(workspace)}")
            serializer = WorkSpaceSerializer(workspace)
            workspace_data = serializer.data
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
# class UserWorkSpaceListView(APIView):
#     permission_classes = [IsAuthenticated]
#     def get(self,request):
#         try:
#             user = request.user
            
#         except Exception as e:
#             return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"message":str(e)})

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


class GetAccessToken(APIView):
    def get(self, request):
        try:
            # Ensure the authorization code is received
            auth_code = request.GET.get("code")
            if not auth_code:
                return Response({"status": 400, "message": "Authorization code not found"})

            token_url = "https://www.linkedin.com/oauth/v2/accessToken"
            data = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": os.getenv("REDIRECT_URI"),
                "client_id": os.getenv("CLIENT_ID"),
                "client_secret": os.getenv("CLIENT_SECRET"),
            }

            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            response = requests.post(token_url, data=data, headers=headers)

            if response.status_code == 200:
                return Response({"status": 200, "message": "Access token received", "data": response.json()})
            else:
                return Response({"status": response.status_code, "message": "Failed to get access token", "details": response.json()})

        except Exception as e:
            return Response({"status": 500, "message": str(e)})
        
        
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
            print(response,'@@@@@@@@@@@@@@@@@@')
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": "Failed to fetch user info", "details": response.json()}

        except Exception as e:
            print(e)
            

#Google auth api
# class LinkedinLoginView(APIView):
#     def post(self, request):
#         email = request.data.get("email", None)
#         first_name = request.data.get("first_name", None)
        
#         if not email:  
#             return Response({  
#                 "status": status.HTTP_400_BAD_REQUEST,  
#                 "message": "Please provide email ",  
#             }) 
#         if not first_name:  
#             return Response({  
#                 "status": status.HTTP_400_BAD_REQUEST,  
#                 "message": "Please provide name ",  
#             }) 
#         user = User.objects.filter(email=email).first()
#         if user:
#             django_login(request, user)
#         else:
#             serializer = GoogleAuthSerializer(data=request.data)
#             if serializer.is_valid(raise_exception=True):
#                 user = serializer.save()
#                 django_login(request, user)

#         token, created = Token.objects.get_or_create(user=user)
#         return Response({
#             "status": status.HTTP_200_OK,
#             "message": "Successfully logged in",
#             "user_id": user.id,
#             "token": token.key,
#             "base_url": baseurl(request),
#         })


class LinkedinLoginView(APIView):  
    def post(self, request):  
        try:
            email = request.data.get("email", None)  
            first_name = request.data.get("first_name", None)  
            last_name = request.data.get("last_name", "")

            if not email or not first_name:  
                return Response({  
                    "status": status.HTTP_400_BAD_REQUEST,  
                    "message": "Please provide both email and first name",  
                })  

            user = User.objects.filter(email=email).first()  

            if user:  
                # User already exists, log them in  
                django_login(request, user)  
            else:  
                # New user, create an account  
                serializer = GoogleAuthSerializer(data={"email": email, "first_name": first_name, "last_name": last_name})  
                if serializer.is_valid():  
                    user = serializer.save()  
                    django_login(request, user)  
                else:  
                    return Response({  
                        "status": status.HTTP_400_BAD_REQUEST,  
                        "message": "Error creating user",  
                        "errors": serializer.errors,  
                    })  

            # Generate token  
            token, _ = Token.objects.get_or_create(user=user)  

            return Response({  
                "status": status.HTTP_200_OK,  
                "message": "Successfully logged in",  
                "user_id": user.id,  
                "token": token.key,  
                "base_url":baseurl(request)
            })  
        except Exception as e:
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,"message":str(e)})