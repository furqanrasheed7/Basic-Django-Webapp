from django.contrib.auth import get_user_model, authenticate, login
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.db import IntegrityError
from django.http import Http404
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from todo.serializers import UserSerializer
from .forms import UserContentForm
from .models import CustomUser


User = get_user_model()

class RegisterAPIView(APIView):
    def post(self, request, format=None):
        data = request.data
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return Response({'message': 'Please provide username, email, and password.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.create_user(username=username, email=email, password=password, is_staff=True)
        except IntegrityError:
            return Response({'message': 'Username or email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': 'User registered successfully.'}, status=status.HTTP_201_CREATED)

class LoginAPIView(APIView):
    def post(self, request, format=None):
        data = request.data
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return Response({'message': 'Please provide both username and password.'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return Response({'message': 'Login successful.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)
            
class UserDetailView(APIView):
    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        user = self.get_object(pk)
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        user = self.get_object(pk)
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        user = self.get_object(pk)
        user.delete()
        return Response({'message': 'User deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
class ForgetPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'message': 'Please provide an email address.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'message': 'User does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        token_generator = default_token_generator
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        current_site = get_current_site(request)
        mail_subject = 'Reset your password'
        message = render_to_string('reset_password_email.html', {
            'user': user,
            'uid': uid,
            'token': token,
            'domain': current_site.domain,
            'protocol': request.scheme,
        })
        email = EmailMessage(mail_subject, message, to=[email])
        email.send()

        return Response({'message': 'Password reset email has been sent.'}, status=status.HTTP_200_OK)

class ChangePasswordView(APIView):
    def post(self, request, format=None):
        uid = request.data.get('uid')
        token = request.data.get('token')
        password = request.data.get('password')

        if not uid or not token or not password:
            return Response({'message': 'Please provide the user ID, token, and new password.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = force_text(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'message': 'Invalid user ID or token.'}, status=status.HTTP_400_BAD_REQUEST)

        token_generator = default_token_generator
        if not token_generator.check_token(user, token):
            return Response({'message': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(password)
        user.save()

        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
    
def user_content_view(request):
    if request.method == 'POST':
        form = UserContentForm(request.POST, request.FILES)
        if form.is_valid():
            user_content = form.save(commit=False)
            user_content.user = CustomUser.objects.get(pk=request.user.pk)
            user_content.save()
            return redirect('content_success')  # Redirect to a success page
    else:
        form = UserContentForm()
    return render(request, 'user_content.html', {'form': form})