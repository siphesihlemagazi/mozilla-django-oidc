import asyncio
import logging
import time
from re import Pattern as re_Pattern
from typing import Mapping
from urllib.parse import quote, urlencode

from asgiref.sync import sync_to_async
from django.contrib.auth import BACKEND_SESSION_KEY
from django.http import HttpResponseRedirect, JsonResponse
from django.utils.crypto import get_random_string

try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse


try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:

    class MiddlewareMixin:
        sync_capable = True
        async_capable = True

        def __init__(self, get_response):
            if get_response is None:
                raise ValueError("get_response must be provided.")
            self.get_response = get_response
            self._async_check()
            super().__init__()

        def __repr__(self):
            return "<%s get_response=%s>" % (
                self.__class__.__qualname__,
                getattr(
                    self.get_response,
                    "__qualname__",
                    self.get_response.__class__.__name__,
                ),
            )

        def _async_check(self):
            """
            If get_response is a coroutine function, turns us into async mode so
            a thread is not consumed during a whole request.
            """
            if asyncio.iscoroutinefunction(self.get_response):
                # Mark the class as async-capable, but do the actual switch
                # inside __call__ to avoid swapping out dunder methods
                self._is_coroutine = asyncio.coroutines._is_coroutine

        def __call__(self, request):
            # Exit out to async mode, if needed
            if asyncio.iscoroutinefunction(self.get_response):
                return self.__acall__(request)
            response = None
            if hasattr(self, "process_request"):
                response = self.process_request(request)
            response = response or self.get_response(request)
            if hasattr(self, "process_response"):
                response = self.process_response(request, response)
            return response

        async def __acall__(self, request):
            """
            Async version of __call__ that is swapped in when an async request
            is running.
            """
            response = None
            if hasattr(self, "process_request"):
                response = await sync_to_async(
                    self.process_request,
                    thread_sensitive=True,
                )(request)
            response = response or await self.get_response(request)
            if hasattr(self, "process_response"):
                response = await sync_to_async(
                    self.process_response,
                    thread_sensitive=True,
                )(request, response)
            return response

from django.utils.functional import cached_property
from django.utils.module_loading import import_string

from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import (
    absolutify,
    add_state_and_verifier_and_nonce_to_session,
    import_from_settings, is_authenticated,
)

LOGGER = logging.getLogger(__name__)


def _destruct_iterable_mapping_values(data):
    for i, elem in enumerate(data):
        if len(elem) != 2:
            raise ValueError(
                'dictionary update sequence element #{} has '
                'length {}; 2 is required.'.format(i, len(elem))
            )
        if not isinstance(elem[0], str):
            raise ValueError('Element key %r invalid, only strings are allowed' % elem[0])
        yield tuple(elem)


class CaseInsensitiveMapping(Mapping):
    """
    Mapping allowing case-insensitive key lookups. Original case of keys is
    preserved for iteration and string representation.

    Example::

        >>> ci_map = CaseInsensitiveMapping({'name': 'Jane'})
        >>> ci_map['Name']
        Jane
        >>> ci_map['NAME']
        Jane
        >>> ci_map['name']
        Jane
        >>> ci_map  # original case preserved
        {'name': 'Jane'}
    """

    def __init__(self, data):
        if not isinstance(data, Mapping):
            data = {k: v for k, v in _destruct_iterable_mapping_values(data)}
        self._store = {k.lower(): (k, v) for k, v in data.items()}

    def __getitem__(self, key):
        return self._store[key.lower()][1]

    def __len__(self):
        return len(self._store)

    def __eq__(self, other):
        return isinstance(other, Mapping) and {
            k.lower(): v for k, v in self.items()
        } == {
            k.lower(): v for k, v in other.items()
        }

    def __iter__(self):
        return (original_key for original_key, value in self._store.values())

    def __repr__(self):
        return repr({key: value for key, value in self._store.values()})

    def copy(self):
        return self


class HttpHeaders(CaseInsensitiveMapping):
    HTTP_PREFIX = 'HTTP_'
    # PEP 333 gives two headers which aren't prepended with HTTP_.
    UNPREFIXED_HEADERS = {'CONTENT_TYPE', 'CONTENT_LENGTH'}

    def __init__(self, environ):
        headers = {}
        for header, value in environ.items():
            name = self.parse_header_name(header)
            if name:
                headers[name] = value
        super().__init__(headers)

    @classmethod
    def parse_header_name(cls, header):
        if header.startswith(cls.HTTP_PREFIX):
            header = header[len(cls.HTTP_PREFIX):]
        elif header not in cls.UNPREFIXED_HEADERS:
            return None
        return header.replace('_', '-').title()


class SessionRefresh(MiddlewareMixin):
    """Refreshes the session with the OIDC RP after expiry seconds

    For users authenticated with the OIDC RP, verify tokens are still valid and
    if not, force the user to re-authenticate silently.

    """

    def __init__(self, get_response):
        super(SessionRefresh, self).__init__(get_response)
        self.OIDC_EXEMPT_URLS = self.get_settings("OIDC_EXEMPT_URLS", [])
        self.OIDC_OP_AUTHORIZATION_ENDPOINT = self.get_settings(
            "OIDC_OP_AUTHORIZATION_ENDPOINT"
        )
        self.OIDC_RP_CLIENT_ID = self.get_settings("OIDC_RP_CLIENT_ID")
        self.OIDC_STATE_SIZE = self.get_settings("OIDC_STATE_SIZE", 32)
        self.OIDC_AUTHENTICATION_CALLBACK_URL = self.get_settings(
            "OIDC_AUTHENTICATION_CALLBACK_URL",
            "oidc_authentication_callback",
        )
        self.OIDC_RP_SCOPES = self.get_settings("OIDC_RP_SCOPES", "openid email")
        self.OIDC_USE_NONCE = self.get_settings("OIDC_USE_NONCE", True)
        self.OIDC_NONCE_SIZE = self.get_settings("OIDC_NONCE_SIZE", 32)

    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

    @cached_property
    def exempt_urls(self):
        """Generate and return a set of url paths to exempt from SessionRefresh

        This takes the value of ``settings.OIDC_EXEMPT_URLS`` and appends three
        urls that mozilla-django-oidc uses. These values can be view names or
        absolute url paths.

        :returns: list of url paths (for example "/oidc/callback/")

        """
        exempt_urls = []
        for url in self.OIDC_EXEMPT_URLS:
            if not isinstance(url, re_Pattern):
                exempt_urls.append(url)
        exempt_urls.extend(
            [
                "oidc_authentication_init",
                "oidc_authentication_callback",
                "oidc_logout",
            ]
        )

        return set(
            [url if url.startswith("/") else reverse(url) for url in exempt_urls]
        )

    @cached_property
    def exempt_url_patterns(self):
        """Generate and return a set of url patterns to exempt from SessionRefresh

        This takes the value of ``settings.OIDC_EXEMPT_URLS`` and returns the
        values that are compiled regular expression patterns.

        :returns: list of url patterns (for example,
            ``re.compile(r"/user/[0-9]+/image")``)
        """
        exempt_patterns = set()
        for url_pattern in self.OIDC_EXEMPT_URLS:
            if isinstance(url_pattern, re_Pattern):
                exempt_patterns.add(url_pattern)
        return exempt_patterns

    def is_refreshable_url(self, request):
        """Takes a request and returns whether it triggers a refresh examination

        :arg HttpRequest request:

        :returns: boolean

        """
        # Do not attempt to refresh the session if the OIDC backend is not used
        backend_session = request.session.get(BACKEND_SESSION_KEY)
        is_oidc_enabled = True
        if backend_session:
            auth_backend = import_string(backend_session)
            is_oidc_enabled = issubclass(auth_backend, OIDCAuthenticationBackend)

        return (
            request.method == "GET"
            and is_authenticated(request.user)
            and is_oidc_enabled
            and request.path not in self.exempt_urls
            and not any(pat.match(request.path) for pat in self.exempt_url_patterns)
        )

    def process_request(self, request):
        if not self.is_refreshable_url(request):
            LOGGER.debug("request is not refreshable")
            return

        expiration = request.session.get("oidc_id_token_expiration", 0)
        now = time.time()
        if expiration > now:
            # The id_token is still valid, so we don't have to do anything.
            LOGGER.debug("id token is still valid (%s > %s)", expiration, now)
            return

        LOGGER.debug("id token has expired")
        # The id_token has expired, so we have to re-authenticate silently.
        auth_url = self.OIDC_OP_AUTHORIZATION_ENDPOINT
        client_id = self.OIDC_RP_CLIENT_ID
        state = get_random_string(self.OIDC_STATE_SIZE)

        # Build the parameters as if we were doing a real auth handoff, except
        # we also include prompt=none.
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": absolutify(
                request, reverse(self.OIDC_AUTHENTICATION_CALLBACK_URL)
            ),
            "state": state,
            "scope": self.OIDC_RP_SCOPES,
            "prompt": "none",
        }

        params.update(self.get_settings("OIDC_AUTH_REQUEST_EXTRA_PARAMS", {}))

        if self.OIDC_USE_NONCE:
            nonce = get_random_string(self.OIDC_NONCE_SIZE)
            params.update({"nonce": nonce})

        add_state_and_verifier_and_nonce_to_session(request, state, params)

        request.session["oidc_login_next"] = request.get_full_path()

        query = urlencode(params, quote_via=quote)
        redirect_url = "{url}?{query}".format(url=auth_url, query=query)

        if not getattr(request, "headers", None):
            request.headers = HttpHeaders(request.META)

        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            # Almost all XHR request handling in client-side code struggles
            # with redirects since redirecting to a page where the user
            # is supposed to do something is extremely unlikely to work
            # in an XHR request. Make a special response for these kinds
            # of requests.
            # The use of 403 Forbidden is to match the fact that this
            # middleware doesn't really want the user in if they don't
            # refresh their session.
            response = JsonResponse({"refresh_url": redirect_url}, status=403)
            response["refresh_url"] = redirect_url
            return response
        return HttpResponseRedirect(redirect_url)
