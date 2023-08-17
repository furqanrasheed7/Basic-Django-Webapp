from django import forms
from .models import UserContent

class UserContentForm(forms.ModelForm):
    class Meta:
        model = UserContent
        fields = ['text_content', 'file_upload']
