from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

from portal.models import DistributorApplication

User = get_user_model()

ROLE_CHOICES = [
    ("Developer", "Developer"),
    ("Administrator", "Administrator"),
    ("Manager", "Manager"),
    ("Distributor", "Distributor"),
    ("Auditor", "Auditor"),
]


def apply_bootstrap(form):
    for field in form.fields.values():
        field.widget.attrs.setdefault("class", "form-control")
        field.widget.attrs.setdefault("autocomplete", "off")


class UserCreateForm(forms.ModelForm):
    role = forms.ChoiceField(choices=ROLE_CHOICES)
    password1 = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ["username", "email", "is_active"]

    def clean_password1(self):
        pwd = self.cleaned_data.get("password1")
        validate_password(pwd)
        return pwd

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password1") != cleaned.get("password2"):
            self.add_error("password2", "Passwords do not match.")
        return cleaned

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserEditForm(forms.ModelForm):
    role = forms.ChoiceField(choices=ROLE_CHOICES)

    class Meta:
        model = User
        fields = ["email", "is_active"]


class DistributorApplicationForm(forms.ModelForm):
    class Meta:
        model = DistributorApplication
        fields = [
            "full_name",
            "email",
            "mobile",
            "company_name",
            "location",
            "notes",
        ]
