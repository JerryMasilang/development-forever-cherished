from django import forms
from django.core.exceptions import ValidationError
from portal.models import UserProfile
from django.contrib.auth import get_user_model

User = get_user_model()


class ProfileSettingsForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ["display_name", "contact_number", "organization", "avatar"]


class EmailChangeForm(forms.Form):
    new_email = forms.EmailField()

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean_new_email(self):
        new_email = self.cleaned_data["new_email"].lower()
        if self.user and self.user.email.lower() == new_email:
            raise ValidationError("New email must be different.")
        return new_email
