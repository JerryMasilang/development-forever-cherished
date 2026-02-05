from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.db.models import Q

User = get_user_model()


class EmailOrUsernameBackend(ModelBackend):

    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return None

        try:
            user = User.objects.get(
                Q(email__iexact=username) | Q(username__iexact=username)
            )
        except User.DoesNotExist:
            return None

        # if user.check_password(password) and self.user_can_authenticate(user):
        if user.check_password(password):
            return user
        return None


from django.contrib.auth.backends import ModelBackend


class PortalAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        user = super().authenticate(request, username=username, password=password)

        # IMPORTANT:
        # Do NOT block inactive users here.
        # Let the AuthenticationForm handle messaging.
        return user
