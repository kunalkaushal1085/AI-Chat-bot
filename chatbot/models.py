from django.db import models
from django.contrib.auth.models import User



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
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} - {self.user.username}"