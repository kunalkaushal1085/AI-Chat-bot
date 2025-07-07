
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
    path('profile/', UserProfileView.as_view(), name='user-profile'),# get profile
    path('create-workspace', WorkSpaceView.as_view(), name='create-workspace'),
    path('user/workspaces', UserWorkSpaceListView.as_view(), name='user-workspaces'),
    path('workspace/<int:workspace_id>/', UserWorkSpaceListView.as_view(), name='user-workspace-delete'),#delete workspace
    path('workspace/<int:workspace_id>/update/', UserWorkSpaceListView.as_view(), name='workspace-update'),#update workspace
    path('workspace/set-active/', SetActiveWorkspaceView.as_view(), name='set-active-workspace'),# active workspace
    path('get-auth-url', GetAuthorizationUrl .as_view(), name='authurl'),
    # path('linkedin/login', LinkedInRedirectView.as_view(), name='linkedin/login/'),
    # path('user-info', GetUserInfo.as_view(), name='getuser-info'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('facebook/callback/', FacebookCallbackView.as_view(), name='facebook-callback'),
    path('facebook/page/', FacebookPagesView.as_view(), name='facebook-get-page'),
    # path('facebook/send-post/', FacebookSendPostView.as_view(), name='facebook-send-post'),
    path('social/send-post/', SocialPostView.as_view(), name='social-send-post'),
    path('oauth/login', LinkedInOAuthLoginView.as_view(), name='linkedin-auth-login'),
    path('oauth/refresh/', LinkedInRefreshTokenView.as_view(), name='linkedin-refresh-token'),
    path('linkedin/post/', LinkedInPostView.as_view(), name='linkedin-post'),

   
]






