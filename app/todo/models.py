from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

# Create your models here.
class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        is_staff = extra_fields.pop('is_staff', False)  # Remove is_staff from extra_fields
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.is_staff = is_staff  # Set is_staff directly
        user.save(using=self._db)
        return user


class CustomUser(AbstractBaseUser, PermissionsMixin):
    # Remove the 'username' field since it's already included in AbstractUser
    username = models.CharField(max_length=30, unique=True)

    email = models.EmailField(max_length=255, unique=True)

    # Add related_name to groups and user_permissions
    groups = models.ManyToManyField(
        'auth.Group', related_name='custom_users', blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission', related_name='custom_users', blank=True
    )

    def __str__(self):
        return self.username
    
    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['email']


class CustomUserGroup(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='custom_user_groups')
    group = models.ForeignKey('auth.Group', on_delete=models.CASCADE, related_name='custom_users_in_group')

class UserContent(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    text_content = models.TextField()
    file_upload = models.FileField(upload_to='uploads/')
    timestamp = models.DateTimeField(auto_now_add=True)
