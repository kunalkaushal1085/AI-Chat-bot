from django.contrib.auth.models import User
from rest_framework import serializers
from .models import UserProfile,WorkSpace


# User Registration Serializer
class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            username=validated_data['email'],  # Use the email as the username
        )
        return user

#User Profile
class UserProfileSerializer(serializers.ModelSerializer):
    business_type = serializers.SerializerMethodField()
    primary_goal = serializers.SerializerMethodField()

    def get_business_type(self, obj):
        return obj.business_type.split(",") if obj.business_type else []

    def get_primary_goal(self, obj):
        return obj.primary_goal.split(",") if obj.primary_goal else []

    class Meta:
        model = UserProfile
        fields = ["name", "business_type", "primary_goal"]

class WorkSpaceSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkSpace
        fields = ['id', 'user', 'name', 'description', 'created_at']    # add id
        read_only_fields = ['id', 'user', 'created_at']


# class GoogleAuthSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ['id', 'first_name','email']

#     def validate_email(self, value):
#         """
#         Check if the email address is unique.
#         """
#         if User.objects.filter(email=value).exists():
#             raise serializers.ValidationError('This email address is already in use.')
#         return value

#     def create(self, validated_data):
#         username = validated_data['email'].split('@')[0]
#         user = User.objects.create(
#             username=username,
#             email=validated_data['email'],
#             first_name=validated_data['first_name'],
#             last_name=validated_data['last_name'],
#         )
#         return user

class GoogleAuthSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "email"]

    def create(self, validated_data):
        # Extract username from email
        username = validated_data["email"].split("@")[0]
        
        user = User.objects.create_user(
            username=username,
            email=validated_data["email"],
            first_name=validated_data["first_name"],
            last_name=validated_data.get("last_name", ""),
            password=None,
        )
        return user