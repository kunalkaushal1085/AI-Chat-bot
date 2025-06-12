
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
    path('user/workspaces', UserWorkSpaceListView.as_view(), name='user-workspaces'),
    path('workspace/<int:workspace_id>/', UserWorkSpaceListView.as_view(), name='user-workspace-delete'),#delete workspace
    path('workspace/<int:workspace_id>/update/', UserWorkSpaceListView.as_view(), name='workspace-update'),#update workspace
    path('workspace/set-active/', SetActiveWorkspaceView.as_view(), name='set-active-workspace'),# active workspace
    path('get-auth-url', GetAuthorizationUrl .as_view(), name='authurl'),
    path('linkedin/login', LinkedInRedirectView.as_view(), name='linkedin/login/'),
    path('user-info', GetUserInfo.as_view(), name='getuser-info'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),

   
]






