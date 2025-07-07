from django.contrib.auth.models import User
from rest_framework import serializers
from .models import UserProfile,WorkSpace


# User Registration Serializer
class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

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
        fields = ["id","name", "business_type", "primary_goal"]

class WorkSpaceSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkSpace
        fields = ['id', 'user', 'name', 'description','image','created_at'] # add id
        read_only_fields = ['id', 'user', 'created_at']

