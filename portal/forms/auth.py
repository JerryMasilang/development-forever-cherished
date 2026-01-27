from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm

from portal.models import DistributorApplication


class PortalAuthenticationForm(AuthenticationForm):
    """
    Your login form (works with your custom auth backends).
    Keep it simple unless you have extra validation rules.
    """

    username = forms.CharField(
        label="Email or Username",
        widget=forms.TextInput(attrs={"class": "form-control", "autofocus": True}),
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"class": "form-control"}),
    )


class DistributorApplicationForm(forms.ModelForm):
    class Meta:
        model = DistributorApplication
        fields = ["full_name", "email", "mobile", "company_name", "location", "notes"]
        widgets = {
            "full_name": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
            "mobile": forms.TextInput(attrs={"class": "form-control"}),
            "company_name": forms.TextInput(attrs={"class": "form-control"}),
            "location": forms.TextInput(attrs={"class": "form-control"}),
            "notes": forms.Textarea(attrs={"class": "form-control", "rows": 4}),
        }


class PortalPasswordResetForm(PasswordResetForm):
    pass
