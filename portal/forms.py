from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import DistributorApplication
from django.contrib.auth.forms import AuthenticationForm
from django import forms
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.conf import settings
from django.contrib.auth import authenticate
from django.utils.html import format_html

# SYNC TEST: forms.py edited locally
# SYNC TEST: forms.py edited locally
# SYNC TEST: forms.py edited on GitHub
# SYNC TEST: forms.py edited on GitHub


User = get_user_model()



def apply_bootstrap(form):
    """
    Apply Bootstrap 5 classes to all fields so they render correctly in templates.
    """
    for name, field in form.fields.items():
        widget = field.widget

        # checkbox
        if widget.__class__.__name__ == "CheckboxInput":
            existing = widget.attrs.get("class", "")
            widget.attrs["class"] = (existing + " form-check-input").strip()
        else:
            existing = widget.attrs.get("class", "")
            widget.attrs["class"] = (existing + " form-control").strip()

        # make selects also look like bootstrap (still form-control works fine)
        widget.attrs.setdefault("autocomplete", "off")




ROLE_CHOICES = [
    ("Developer", "Developer"),
    ("Administrator", "Administrator"),
    ("Manager", "Manager"),
    ("Distributor", "Distributor"),
    ("Auditor", "Auditor"),
]


class PortalAuthenticationForm(AuthenticationForm):
    def confirm_login_allowed(self, user):
        """
        Override Django default behavior.
        This is where Django blocks inactive users.
        """
        if not user.is_active:
            admin_email = getattr(
                settings, "ADMIN_SUPPORT_EMAIL", "admin@yourdomain.com"
            )
            raise forms.ValidationError(
                format_html(
                    "Account disabled. Contact administrator: "
                    '<a href="mailto:{0}">{0}</a>',
                    admin_email,
                ),
                code="inactive",
            )

    def clean(self):
        """
        Let AuthenticationForm handle authentication flow.
        We do NOT check is_active here anymore.
        """
        return super().clean()


class UserCreateForm(forms.ModelForm):
    role = forms.ChoiceField(choices=ROLE_CHOICES, widget=forms.Select(attrs={"class": "form-select"}))
    password1 = forms.CharField(widget=forms.PasswordInput(attrs={"class": "form-control"}), label="Password")
    password2 = forms.CharField(widget=forms.PasswordInput(attrs={"class": "form-control"}), label="Confirm Password")

    primary_mfa_method = forms.ChoiceField(
        choices=[("totp", "Authenticator (TOTP)"), ("email", "Email OTP")],
        initial="totp",
        required=True,
        widget=forms.Select(attrs={"class": "form-select"}),
    )
    email_fallback_enabled = forms.BooleanField(
        required=False,
        initial=True,
        label="Enable OTP fallback",
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )

    class Meta:
        model = User
        fields = ["username", "email", "is_active"]
        widgets = {
            "username": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # is_active is part of ModelForm widgets; set it here
        self.fields["is_active"].widget.attrs.update({"class": "form-check-input"})
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

        # ✅ set hashed password
        user.set_password(self.cleaned_data["password1"])

        if commit:
            user.save()

            # ✅ update profile values (signal should have created profile)
            if hasattr(user, "profile"):
                user.profile.role = self.cleaned_data["role"]
                user.profile.primary_mfa_method = self.cleaned_data["primary_mfa_method"]
                user.profile.email_fallback_enabled = self.cleaned_data["email_fallback_enabled"]
                user.profile.save()

        return user


class UserEditForm(forms.ModelForm):
    role = forms.ChoiceField(choices=ROLE_CHOICES, widget=forms.Select(attrs={"class": "form-select"}))
    primary_mfa_method = forms.ChoiceField(
        choices=[("totp", "Authenticator (TOTP)"), ("email", "Email OTP")],
        required=True,
        widget=forms.Select(attrs={"class": "form-select"}),
    )
    email_fallback_enabled = forms.BooleanField(
        required=False,
        label="Enable OTP fallback",
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )

    class Meta:
        model = User
        fields = ["email", "is_active"]
        widgets = {
            "email": forms.EmailInput(attrs={"class": "form-control"}),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.get("instance")
        super().__init__(*args, **kwargs)

        self.fields["is_active"].widget.attrs.update({"class": "form-check-input"})

        if user and hasattr(user, "profile"):
            self.fields["role"].initial = user.profile.role
            self.fields["primary_mfa_method"].initial = getattr(user.profile, "primary_mfa_method", "totp")
            self.fields["email_fallback_enabled"].initial = getattr(user.profile, "email_fallback_enabled", True)

    def save(self, commit=True):
        user = super().save(commit=commit)
        if hasattr(user, "profile"):
            user.profile.role = self.cleaned_data["role"]
            user.profile.primary_mfa_method = self.cleaned_data["primary_mfa_method"]
            user.profile.email_fallback_enabled = self.cleaned_data["email_fallback_enabled"]
            user.profile.save()
        return user

class DistributorApplicationForm(forms.ModelForm):
    class Meta:
        model = DistributorApplication
        fields = ["full_name", "email", "mobile", "company_name", "location", "notes"]


class PortalPasswordResetForm(PasswordResetForm):
    """
    Fixes NoReverseMatch by generating reset URLs using the portal namespace.
    """

    def save(
        self,
        domain_override=None,
        subject_template_name="registration/password_reset_subject.txt",
        email_template_name="registration/password_reset_email.html",
        use_https=False,
        token_generator=None,
        from_email=None,
        request=None,
        html_email_template_name=None,
        extra_email_context=None,
    ):

        # Force the correct namespaced URL name for the reset-confirm link
        if extra_email_context is None:
            extra_email_context = {}
        extra_email_context["password_reset_confirm_url_name"] = (
            "portal:password_reset_confirm"
        )

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
