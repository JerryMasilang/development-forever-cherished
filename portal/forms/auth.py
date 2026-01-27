from django import forms
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordResetForm,
    PasswordChangeForm,
)
from django.core.exceptions import ValidationError
from django.utils.html import format_html

from portal.models import PasswordHistory


class PortalAuthenticationForm(AuthenticationForm):
    def confirm_login_allowed(self, user):
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


class PortalPasswordResetForm(PasswordResetForm):
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
        if extra_email_context is None:
            extra_email_context = {}
        extra_email_context["password_reset_confirm_url_name"] = (
            "portal:password_reset_confirm"
        )
        return super().save(
            domain_override,
            subject_template_name,
            email_template_name,
            use_https,
            token_generator,
            from_email,
            request,
            html_email_template_name,
            extra_email_context,
        )


class PortalPasswordChangeForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field in self.fields.values():
            field.widget.attrs.setdefault("class", "form-control")
            field.widget.attrs.pop("autofocus", None)

    def clean_new_password1(self):
        new_pwd = self.cleaned_data.get("new_password1")
        if not new_pwd:
            return new_pwd

        recent = PasswordHistory.objects.filter(user=self.user).order_by("-created_at")[:2]
        from django.contrib.auth.hashers import check_password

        for item in recent:
            if check_password(new_pwd, item.password_hash):
                raise ValidationError("You cannot reuse your last 2 passwords.")

        return new_pwd
