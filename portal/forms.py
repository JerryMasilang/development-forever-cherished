from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import DistributorApplication
from django.contrib.auth.forms import AuthenticationForm
from django import forms
from django.contrib.auth.forms import PasswordResetForm

User = get_user_model()

ROLE_CHOICES = [
    ("Developer", "Developer"),
    ("Administrator", "Administrator"),
    ("Manager", "Manager"),
    ("Distributor", "Distributor"),
    ("Auditor", "Auditor"),
]

class PortalAuthenticationForm(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "Enter username",
            "autofocus": "autofocus",
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "Enter password",
        })
    )

class UserCreateForm(forms.ModelForm):
    role = forms.ChoiceField(choices=ROLE_CHOICES)
    password1 = forms.CharField(widget=forms.PasswordInput, label="Password")
    password2 = forms.CharField(widget=forms.PasswordInput, label="Confirm Password")

    class Meta:
        model = User
        fields = ["username", "email", "is_active"]

    def clean_password1(self):
        pwd = self.cleaned_data.get("password1")
        validate_password(pwd)
        return pwd

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1")
        p2 = cleaned.get("password2")
        if p1 and p2 and p1 != p2:
            self.add_error("password2", "Passwords do not match.")
        return cleaned

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
            # profile should be created by your signal
            if hasattr(user, "profile"):
                user.profile.role = self.cleaned_data["role"]
                user.profile.save(update_fields=["role"])
        return user


class UserEditForm(forms.ModelForm):
    role = forms.ChoiceField(choices=ROLE_CHOICES)

    class Meta:
        model = User
        fields = ["email", "is_active"]

    def __init__(self, *args, **kwargs):
        user = kwargs.get("instance")
        super().__init__(*args, **kwargs)
        if user and hasattr(user, "profile"):
            self.fields["role"].initial = user.profile.role

    def save(self, commit=True):
        user = super().save(commit=commit)
        if hasattr(user, "profile"):
            user.profile.role = self.cleaned_data["role"]
            user.profile.save(update_fields=["role"])
        return user

class DistributorApplicationForm(forms.ModelForm):
    class Meta:
        model = DistributorApplication
        fields = ["full_name", "email", "mobile", "company_name", "location", "notes"]


class PortalPasswordResetForm(PasswordResetForm):
    """
    Fixes NoReverseMatch by generating reset URLs using the portal namespace.
    """
    def save(self, domain_override=None,
             subject_template_name='registration/password_reset_subject.txt',
             email_template_name='registration/password_reset_email.html',
             use_https=False, token_generator=None,
             from_email=None, request=None,
             html_email_template_name=None,
             extra_email_context=None):

        # Force the correct namespaced URL name for the reset-confirm link
        if extra_email_context is None:
            extra_email_context = {}
        extra_email_context["password_reset_confirm_url_name"] = "portal:password_reset_confirm"

        return super().save(
            domain_override=domain_override,
            subject_template_name=subject_template_name,
            email_template_name=email_template_name,
            use_https=use_https,
            token_generator=token_generator,
            from_email=from_email,
            request=request,
            html_email_template_name=html_email_template_name,
            extra_email_context=extra_email_context,
        )