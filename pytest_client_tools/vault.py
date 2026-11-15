# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

"""
Resolution of ``@vault:`` sentinels in the settings.

A sentinel is a placeholder for a value stored in a Vault kv2 secret
store, with the form::

    @vault:<path>:<key>

where ``<path>`` is the logical path of the secret (for example
``apps/example/example-secret``) and ``<key>`` is the name of the value
within that secret. A sentinel can be the value of any settings key, in
any section and any Dynaconf environment, also as an element of a list
value.

The credentials for the Vault server come from the environment, and
never from the command line:

- ``VAULT_TOKEN``: a static token;
- ``VAULT_ROLE_ID`` and ``VAULT_SECRET_ID``: an AppRole, exchanged for
  a client token with a login request;
- ``VAULT_ADDR``: the address of the Vault server, required whenever
  the credentials are set: there is no default address, so the
  resolver only ever contacts the server it was explicitly pointed
  at, and credentials without an address fail the resolution of
  every sentinel (an error message by default, fatal in strict
  mode);
- ``VAULT_SKIP_VERIFY``: skip the validation of the TLS certificate of
  the Vault server, needed with self-signed certificates; this makes
  the connection vulnerable to man-in-the-middle attacks.

Reads follow only the redirects that stay on the origin (scheme, host
and port) of ``VAULT_ADDR``: a redirect to a different origin is
refused with an error naming the target, so that the client token is
never sent to a server the user did not configure. A Vault cluster
that redirects across hosts (for example an HA cluster redirecting to
the active node) must be reached by pointing ``VAULT_ADDR`` at a load
balancer or at the active node itself.

Secret values are never logged: the error messages name paths and keys
only.
"""

import os
from urllib.parse import urljoin, urlsplit

import requests

# prefix that marks a settings value as a Vault sentinel
SENTINEL_PREFIX = "@vault:"

# environment variable that turns sentinels that cannot be resolved
# into a fatal error, instead of treating them as absent settings
STRICT_ENV_VAR = "PYTEST_CLIENT_TOOLS_VAULT_REQUIRED"

# seconds to wait for each Vault request
REQUEST_TIMEOUT = 10

# the HTTP statuses whose response may point the client at another
# URL, and how many of them to follow at most
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_MAX_REDIRECTS = 10

_TRUTHY_VALUES = ("1", "true", "yes", "on")


class VaultError(Exception):
    """
    A sentinel could not be resolved.

    The message names the Vault path and the key involved, never their
    value.
    """


def is_sentinel(value):
    """
    Whether a value is a Vault sentinel.

    :type value: str
    """
    return isinstance(value, str) and value.startswith(SENTINEL_PREFIX)


def contains_sentinel(value):
    """
    Whether a settings value is a Vault sentinel, or a list or
    dictionary holding one among its (nested) elements.
    """
    if isinstance(value, str):
        return is_sentinel(value)
    if isinstance(value, dict):
        return any(contains_sentinel(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_sentinel(item) for item in value)
    return False


def parse_sentinel(value):
    """
    Split a sentinel into the ``(path, key)`` pair of the value it
    refers to.

    :param value: the sentinel to split
    :type value: str
    :raises VaultError: if the sentinel is malformed
    """
    _, _, target = value.partition(SENTINEL_PREFIX)
    path, separator, key = target.rpartition(":")
    if not (separator and path and key):
        raise VaultError(
            "malformed Vault sentinel {0!r}: expected the form"
            " '@vault:<path>:<key>'".format(value)
        )
    return path, key


class VaultResolver:
    """
    Resolves Vault sentinels into the values stored in a Vault kv2
    secret store.

    An instance holds the client token (taken directly from
    ``VAULT_TOKEN``, or obtained once with an AppRole login) and a
    cache of the outcomes, so that resolving the same sentinel again
    does not issue further requests.
    """

    def __init__(self, environ=None):
        self._environ = os.environ if environ is None else environ
        self._token = None
        self._cache = {}
        # a failure of the connection or of the login is a property of
        # the server or of the credentials, not of the individual
        # sentinel: it is remembered here for the lifetime of the
        # resolver, so that at most one login attempt and one request
        # timeout are paid per run, however many sentinels fail
        self._login_failure = None
        self._connection_failure = None

    @property
    def configured(self):
        """
        Whether the credentials for the Vault server are available: a
        static token, or a complete AppRole (both role id and secret
        id).
        """
        if self._environ.get("VAULT_TOKEN", "").strip():
            return True
        return bool(
            self._environ.get("VAULT_ROLE_ID", "").strip()
            and self._environ.get("VAULT_SECRET_ID", "").strip()
        )

    @property
    def strict(self):
        """
        Whether sentinels that cannot be resolved must raise an error
        instead of being treated as absent settings.
        """
        value = self._environ.get(STRICT_ENV_VAR, "").strip().lower()
        return value in _TRUTHY_VALUES

    @property
    def address(self):
        """
        The address of the Vault server, or an empty string when
        ``VAULT_ADDR`` is not set: there is no default address, so
        credentials without an address are a configuration error (see
        :meth:`resolve`).
        """
        return self._environ.get("VAULT_ADDR", "").strip()

    @property
    def verify(self):
        """
        Whether the TLS certificate of the Vault server must be
        validated.
        """
        skip = self._environ.get("VAULT_SKIP_VERIFY", "").strip().lower()
        return skip not in _TRUTHY_VALUES

    def resolve(self, value):
        """
        Resolve a sentinel into the value it refers to.

        :param value: the sentinel to resolve
        :type value: str
        :raises VaultError: if the value cannot be resolved
        """
        if not self.configured:
            raise VaultError(
                "no Vault credentials: set VAULT_TOKEN, or VAULT_ROLE_ID and"
                " VAULT_SECRET_ID"
            )
        if not self.address:
            # no default address: sending the credentials to a host the
            # user never configured must never happen
            raise VaultError(
                "Vault credentials are set but VAULT_ADDR is not: set it to"
                " the address of the Vault server"
            )
        path, key = parse_sentinel(value)
        # a failure of the connection or of the login was paid already:
        # do not pay it once per sentinel (see __init__)
        if self._connection_failure is not None:
            raise self._connection_failure
        if self._login_failure is not None:
            raise self._login_failure
        if (path, key) not in self._cache:
            try:
                self._cache[(path, key)] = ("ok", self._fetch(path, key))
            except VaultError as error:
                # cache the failure too, so that resolving the same
                # sentinel again does not repeat the request
                self._cache[(path, key)] = ("error", error)
        status, resolved = self._cache[(path, key)]
        if status == "error":
            raise resolved
        return resolved

    def _fetch(self, path, key):
        mount, _, rest = path.partition("/")
        if not rest:
            raise VaultError(
                "invalid Vault path {0!r}: expected '<mount>/<path>'".format(path)
            )
        token = self._get_token()
        # the path of the sentinel is the logical path of the kv2
        # secret: the data API inserts '/data/' right after the mount
        # prefix
        url = "{0}/v1/{1}/data/{2}".format(self.address.rstrip("/"), mount, rest)
        try:
            response = self._request(
                requests.get,
                url,
                headers={"X-Vault-Token": token},
                verify=self.verify,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as error:
            # the message of a requests exception can embed the URL of
            # the request: name only the class of the error, to avoid
            # leaking the address of the Vault server
            failure = VaultError(
                "cannot read Vault path {0!r}: {1}".format(path, type(error).__name__)
            )
            # a failure to reach the server is a property of the
            # connection, not of the individual sentinel: remember it
            # so that the timeout is paid once per run at most
            self._connection_failure = failure
            raise failure
        if response.status_code != 200:
            raise VaultError(
                "cannot read Vault path {0!r}: HTTP {1}".format(
                    path, response.status_code
                )
            )
        try:
            data = response.json()["data"]["data"]
        except (ValueError, KeyError, TypeError):
            raise VaultError("malformed Vault response for path {0!r}".format(path))
        if key not in data:
            raise VaultError(
                "key {0!r} not found at Vault path {1!r}".format(key, path)
            )
        if not isinstance(data[key], str):
            raise VaultError(
                "the value of key {0!r} at Vault path {1!r} is not a"
                " string".format(key, path)
            )
        return data[key]

    def _request(self, request, url, **kwargs):
        """
        Send a request to the Vault server, following the redirects
        that stay on the origin of ``VAULT_ADDR`` and refusing the
        others.

        ``requests`` follows redirects by default and forwards custom
        headers — ``X-Vault-Token`` included — to whatever host a
        redirect points at, so a Vault endpoint answering with a
        redirect to another host would receive the client token. The
        redirects are therefore followed one hop at a time, and only
        while the target stays on the same scheme, host and port as
        the configured address; a redirect to a different origin is
        refused with an error naming the target, and no request is
        sent to it.

        :param request: the ``requests`` function to send the request
            with, called with ``allow_redirects=False``
        :param url: the URL to request
        :param kwargs: the keyword arguments of the request
        """
        for _ in range(_MAX_REDIRECTS):
            response = request(url, allow_redirects=False, **kwargs)
            location = (
                response.headers.get("Location")
                if response.status_code in _REDIRECT_STATUSES
                else None
            )
            if not location:
                return response
            target = urljoin(url, location)
            try:
                target_origin = self._origin(target)
            except ValueError:
                # a target that cannot be parsed cannot be proven to
                # stay on the configured origin: refuse it
                target_origin = None
            if target_origin != self._origin(self.address):
                raise VaultError(
                    "Vault redirected to {0}, a different origin than the"
                    " one of VAULT_ADDR: refusing to send the Vault"
                    " credentials there".format(target)
                )
            url = target
        raise VaultError("too many redirects from the Vault server")

    @staticmethod
    def _origin(url):
        """
        The ``(scheme, host, port)`` triple a URL points at, with the
        default port of each scheme filled in, so that two spellings
        of the same origin compare equal.

        :raises ValueError: if the URL is too malformed to name a port
        """
        parts = urlsplit(url)
        port = parts.port
        if port is None:
            port = 443 if parts.scheme == "https" else 80
        return (parts.scheme.lower(), (parts.hostname or "").lower(), port)

    def _get_token(self):
        if self._token is None:
            token = self._environ.get("VAULT_TOKEN", "").strip()
            if not token:
                token = self._login()
            self._token = token
        return self._token

    def _login(self):
        """
        Exchange the AppRole for a client token.

        A failed login is remembered for the lifetime of the resolver:
        it is a property of the credentials, not of the individual
        sentinel, so the login is attempted at most once per run.

        :raises VaultError: if the login fails
        """
        role_id = self._environ.get("VAULT_ROLE_ID", "").strip()
        secret_id = self._environ.get("VAULT_SECRET_ID", "").strip()
        url = "{0}/v1/auth/approle/login".format(self.address.rstrip("/"))
        try:
            try:
                response = self._request(
                    requests.post,
                    url,
                    json={"role_id": role_id, "secret_id": secret_id},
                    verify=self.verify,
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.RequestException as error:
                # the message of a requests exception can embed the URL
                # of the request: name only the class of the error
                raise VaultError(
                    "Vault AppRole login failed: {0}".format(type(error).__name__)
                )
            if response.status_code != 200:
                raise VaultError(
                    "Vault AppRole login failed: HTTP {0}".format(response.status_code)
                )
            try:
                token = response.json()["auth"]["client_token"]
            except (ValueError, KeyError, TypeError):
                raise VaultError("Vault AppRole login response has no client token")
            if not token:
                raise VaultError("Vault AppRole login returned an empty client token")
        except VaultError as error:
            self._login_failure = error
            raise
        return token
