from rest_framework import serializers
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import smart_str
from django.utils.http import urlsafe_base64_decode
from rest_framework.exceptions import AuthenticationFailed
from todo.models import CustomUser
from django.db.models import QuerySet

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = "__all__"

    def create(self, validated_data):
        # Remove the is_staff value from validated_data to avoid conflicts
        is_staff = validated_data.pop('is_staff', True)
        
        # Call the create method of the parent class
        user = super().create(validated_data)
        
        # Set is_staff for the created user
        user.is_staff = is_staff
        user.save()
        
        return user



class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')

        if CustomUser.objects.filter(email=email).exists():
            return attrs
        else:
            raise serializers.ValidationError({'email': 'User with this email does not exist.'})


class SetNewPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(min_length=6, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['new_password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            new_password = attrs.get('new_password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = smart_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(id=id)

            if not default_token_generator.check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(new_password)
            user.save()

            return user

        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
