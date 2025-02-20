try:
    from django.urls import path
except ImportError:
    from django.conf.urls import url as path
from django.utils.module_loading import import_string

from mozilla_django_oidc import views
from mozilla_django_oidc.utils import import_from_settings

DEFAULT_CALLBACK_CLASS = "mozilla_django_oidc.views.OIDCAuthenticationCallbackView"
CALLBACK_CLASS_PATH = import_from_settings(
    "OIDC_CALLBACK_CLASS", DEFAULT_CALLBACK_CLASS
)

OIDCCallbackClass = import_string(CALLBACK_CLASS_PATH)


DEFAULT_AUTHENTICATE_CLASS = "mozilla_django_oidc.views.OIDCAuthenticationRequestView"
AUTHENTICATE_CLASS_PATH = import_from_settings(
    "OIDC_AUTHENTICATE_CLASS", DEFAULT_AUTHENTICATE_CLASS
)

OIDCAuthenticateClass = import_string(AUTHENTICATE_CLASS_PATH)

urlpatterns = [
    path("callback/", OIDCCallbackClass.as_view(), name="oidc_authentication_callback"),
    path(
        "authenticate/",
        OIDCAuthenticateClass.as_view(),
        name="oidc_authentication_init",
    ),
    path("logout/", views.OIDCLogoutView.as_view(), name="oidc_logout"),
]
