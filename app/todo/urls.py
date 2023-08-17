from django.urls import path
from .views import RegisterAPIView, LoginAPIView, UserDetailView, ForgetPasswordView, ChangePasswordView, user_content_view


urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='user-register'),
    path('login/', LoginAPIView.as_view(), name='user-login'),
    path('user/<int:pk>/', UserDetailView.as_view(), name='user-detail'),
    path('forget/', ForgetPasswordView.as_view(), name='forget_password'),
    path('change/', ChangePasswordView.as_view(), name='change_password'),
    path('submit/', user_content_view, name='submit_content'),
]
