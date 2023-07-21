try:
    from django.urls import path, include
except ImportError:
    from django.conf.urls import url as path
    from django.conf.urls import include
urlpatterns = [path("namespace/", include(("mozilla_django_oidc.urls", "namespace")))]
