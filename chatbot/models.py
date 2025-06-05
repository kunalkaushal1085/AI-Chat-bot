from django.db import models
from django.contrib.auth.models import User
from datetime import datetime, timedelta
from utils.base import encrypt_data, decrypt_data
from django.utils import timezone


# OTP Model
class OTP(models.Model):
    email = models.EmailField()
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField()
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.email} - {self.otp_code}"


class LoginAttempt(models.Model):
    email = models.EmailField(unique=True)
    failed_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    def is_locked(self):
        return self.locked_until and timezone.now() < self.locked_until


#Profile Model
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    name = models.CharField(max_length=255)
    business_type = models.TextField() 
    primary_goal = models.TextField() 
    created_at = models.DateTimeField(auto_now_add=True) 

    def __str__(self):
        return self.user.username


#create workspace
class WorkSpace(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="work_space")
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=1000)
    image = models.ImageField(upload_to='workspaces/', blank=True, null=True, default='default_image.jpg')
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} - {self.user.username}"
    

class LinkedinToken(models.Model):
    # user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="linkedin_token")
    access_token = models.CharField(max_length=255, null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        """Check if token is expired"""
        if not self.expires_at:
            return True  
        return datetime.now() >= self.expires_at

    @property
    def access_token(self):
        """Decrypt access token when accessed"""
        if self.access_token:
            return decrypt_data(self.access_token)
        return None

    @access_token.setter
    def access_token(self, value):
        """Encrypt access token before saving"""
        if value:
            self.access_token = encrypt_data(value)