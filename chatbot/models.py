from django.db import models
from django.contrib.auth.models import User



# OTP Model
class OTP(models.Model):
    email = models.EmailField()
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField()

    def __str__(self):
        return f"{self.email} - {self.otp_code}"

# Add user profile
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    name = models.CharField(max_length=255)
    business_type = models.TextField() 
    primary_goal = models.TextField()  

    def __str__(self):
        return self.user.username
