from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class CustomUser(AbstractUser):
    # Remove the 'username' field since it's already included in AbstractUser
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

class CustomUserGroup(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='custom_user_groups')
    group = models.ForeignKey('auth.Group', on_delete=models.CASCADE, related_name='custom_users_in_group')
