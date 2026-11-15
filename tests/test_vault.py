# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

"""
Tests for the resolution of the @vault sentinels in the test
configuration.

The Vault server is a local HTTP server that speaks the parts of the
Vault API used by the resolution (the AppRole login and the kv2 data
reads) and serves dummy values: no real Vault server is contacted, and
all the credential-like values are dummy ones.
"""

import contextlib
import json
import os
import pathlib
import socketserver
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import requests
from dynaconf.validator import ValidationError

from pytest_client_tools.test_config import TestConfig as Config
from pytest_client_tools.vault import (
    REQUEST_TIMEOUT,
    VaultError,
    VaultResolver,
)

# Root of the repository, used to make the plugin importable in
# subprocesses run by pytester also when the package is not installed.
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# dummy AppRole and client token accepted by the mock Vault server
DUMMY_ROLE_ID = "dummy-role-id"
DUMMY_SECRET_ID = "dummy-secret-id"
DUMMY_TOKEN = "dummy-client-token"

# the dummy secrets served by the mock Vault server, keyed by the
# logical path of the kv2 secret
DUMMY_SECRETS = {
    "apps/example/example-secret": {
        "username": "dummy-vault-username",
        "password": "dummy-vault-password",
        "key": "dummy-vault-key",
    },
    "apps/example/stage-secret": {
        "password": "dummy-stage-vault-password",
    },
    "apps/example/secrets-secret": {
        "password": "dummy-secrets-vault-password",
        "key": "dummy-secrets-vault-key",
    },
}

# a full, valid external Candlepin configuration whose password is a
# sentinel resolved by the mock Vault server
SENTINEL_SETTINGS = textwrap.dedent("""\
    [default.candlepin]
    host = "candlepin.example.test"
    port = 8443
    prefix = "/candlepin"
    insecure = false
    username = "dummy-username"
    password = "@vault:apps/example/example-secret:password"
    org = "dummy-org"
    environments = ["dummy-env-1"]

    [default.insights]
    legacy_upload = false
    auto_update = false
    """)

# a full, valid external Candlepin configuration whose username and
# password are both sentinels: when they cannot be resolved both keys
# are absent, no validator requires them (each one only when the other
# exists), and the external Candlepin is not considered configured
SENTINEL_CREDENTIALS_SETTINGS = textwrap.dedent("""\
    [default.candlepin]
    host = "candlepin.example.test"
    port = 8443
    prefix = "/candlepin"
    insecure = false
    username = "@vault:apps/example/example-secret:username"
    password = "@vault:apps/example/example-secret:password"
    org = "dummy-org"
    environments = ["dummy-env-1"]

    [default.insights]
    legacy_upload = false
    auto_update = false
    """)


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


class _VaultHandler(BaseHTTPRequestHandler):
    """
    The parts of the Vault API used by the sentinel resolution.

    The server records the requests it serves (as ``(method, path)``
    pairs, for the tests that count the requests) and answers the
    paths listed in its ``redirects`` mapping with a redirect instead
    of a secret, for the tests of the redirect policy.
    """

    def do_POST(self):
        self.server.requests.append(("POST", self.path))
        if self.path != "/v1/auth/approle/login":
            self._send(404, {"errors": ["unknown endpoint"]})
            return
        length = int(self.headers.get("Content-Length", 0))
        request = json.loads(self.rfile.read(length))
        if (
            request.get("role_id") == self.server.role_id
            and request.get("secret_id") == self.server.secret_id
        ):
            self._send(200, {"auth": {"client_token": self.server.token}})
        else:
            self._send(400, {"errors": ["invalid role_id or secret_id"]})

    def do_GET(self):
        self.server.requests.append(("GET", self.path))
        redirect = self.server.redirects.get(self.path)
        if redirect is not None:
            self.send_response(302)
            self.send_header("Location", redirect)
            self.end_headers()
            return
        if not self.path.startswith("/v1/") or "/data/" not in self.path:
            self._send(404, {"errors": ["unknown endpoint"]})
            return
        if self.headers.get("X-Vault-Token") != self.server.token:
            self._send(403, {"errors": ["permission denied"]})
            return
        # the URL path is /v1/<mount>/data/<path>: the logical path of
        # the secret is the two parts joined back together
        _, _, api_path = self.path.partition("/v1/")
        mount, _, rest = api_path.partition("/data/")
        logical_path = "/".join((mount, rest))
        try:
            data = self.server.secrets[logical_path]
        except KeyError:
            self._send(404, {"errors": ["not found"]})
            return
        self._send(200, {"data": {"data": data, "metadata": {}}})

    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # keep the test output clean
        pass


def _make_vault_server():
    """
    A local HTTP server playing the role of the Vault server, serving
    the dummy secrets, recording the requests it serves and ready to
    answer selected paths with a redirect.
    """
    server = _ThreadingHTTPServer(("127.0.0.1", 0), _VaultHandler)
    server.role_id = DUMMY_ROLE_ID
    server.secret_id = DUMMY_SECRET_ID
    server.token = DUMMY_TOKEN
    server.secrets = DUMMY_SECRETS
    server.requests = []
    server.redirects = {}
    return server


@contextlib.contextmanager
def _running(server):
    """
    Serve requests from a background thread for the duration of the
    block.
    """
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join()


@pytest.fixture(scope="session")
def vault_server():
    """
    A local HTTP server playing the role of the Vault server, serving
    the dummy secrets.
    """
    with _running(_make_vault_server()) as server:
        yield server


@pytest.fixture
def vault_env(vault_server, monkeypatch):
    """
    AppRole credentials pointing at the mock Vault server.
    """
    monkeypatch.setenv(
        "VAULT_ADDR", "http://127.0.0.1:{}".format(vault_server.server_port)
    )
    monkeypatch.setenv("VAULT_ROLE_ID", DUMMY_ROLE_ID)
    monkeypatch.setenv("VAULT_SECRET_ID", DUMMY_SECRET_ID)


def test_resolver_reads_configuration_from_the_environment(
    clean_config_env, monkeypatch
):
    """
    The Vault resolver takes its configuration from the environment:
    the address, the credentials, the TLS setting, and the strict mode
    flag.
    """
    resolver = VaultResolver()

    assert resolver.configured is False
    assert resolver.strict is False
    assert resolver.verify is True
    # no default address: the resolver only ever contacts the server
    # it was explicitly pointed at
    assert resolver.address == ""

    monkeypatch.setenv("VAULT_ADDR", "https://vault.example.test:8200")
    assert resolver.address == "https://vault.example.test:8200"

    # an AppRole needs both its parts
    monkeypatch.setenv("VAULT_ROLE_ID", DUMMY_ROLE_ID)
    assert resolver.configured is False
    monkeypatch.setenv("VAULT_SECRET_ID", DUMMY_SECRET_ID)
    assert resolver.configured is True

    monkeypatch.setenv("VAULT_TOKEN", DUMMY_TOKEN)
    assert resolver.configured is True

    monkeypatch.setenv("VAULT_SKIP_VERIFY", "1")
    assert resolver.verify is False

    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_VAULT_REQUIRED", "1")
    assert resolver.strict is True


def test_sentinel_resolved(clean_config_env, vault_env):
    """
    A sentinel value is replaced by the value read from the Vault
    server, and the section of the settings holds a single spelling of
    the key.
    """
    clean_config_env.joinpath("settings.toml").write_text(SENTINEL_SETTINGS)

    test_config = Config()

    # the resolution happens before the validation: the validators saw
    # a real password, and did not reject the configuration
    assert test_config.is_external is True
    assert test_config.get("candlepin", "password") == "dummy-vault-password"
    # the sibling keys keep their values
    assert test_config.get("candlepin", "username") == "dummy-username"
    assert test_config.get("candlepin", "host") == "candlepin.example.test"
    # a single spelling of the key is left in the section
    section = test_config._settings.as_dict()["CANDLEPIN"]
    assert section["PASSWORD"] == "dummy-vault-password"
    assert "password" not in section


def test_sentinel_resolved_in_list_element(clean_config_env, vault_env):
    """
    A sentinel as an element of a list value is resolved element-wise,
    keeping the values of the other elements, with a single spelling of
    the key in the section.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "dummy-password"
            activation_keys = ["dummy-key-1", "@vault:apps/example/example-secret:key"]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))

    test_config = Config()

    assert test_config.get("candlepin", "activation_keys") == [
        "dummy-key-1",
        "dummy-vault-key",
    ]
    assert test_config.is_external is True
    section = test_config._settings.as_dict()["CANDLEPIN"]
    assert section["ACTIVATION_KEYS"] == ["dummy-key-1", "dummy-vault-key"]
    assert "activation_keys" not in section


def test_sentinel_resolved_in_flat_key(clean_config_env, vault_env):
    """
    A sentinel as the value of a flat (top level) key is resolved.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default]
            example_flat_key = "@vault:apps/example/example-secret:password"

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))

    test_config = Config()

    assert test_config.get("example_flat_key") == "dummy-vault-password"


def test_sentinels_resolved_per_environment(clean_config_env, vault_env, monkeypatch):
    """
    The [default] and [stage] environments can point at different Vault
    secrets: the sentinel of the selected environment is the one
    resolved, and switching ENV_FOR_DYNACONF switches the value.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "@vault:apps/example/example-secret:password"
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [stage.candlepin]
            password = "@vault:apps/example/stage-secret:password"

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))

    monkeypatch.setenv("ENV_FOR_DYNACONF", "stage")
    stage_config = Config()
    assert stage_config.environment == "stage"
    assert stage_config.get("candlepin", "password") == "dummy-stage-vault-password"
    # the keys omitted by [stage] keep the [default] values
    assert stage_config.get("candlepin", "host") == "candlepin.example.test"

    monkeypatch.delenv("ENV_FOR_DYNACONF")
    default_config = Config()
    assert default_config.get("candlepin", "password") == "dummy-vault-password"


def test_no_credentials_sentinels_absent(clean_config_env):
    """
    Without Vault credentials the sentinel-valued keys are treated as
    absent, exactly as if they were never defined: the external
    Candlepin is not considered configured, the tests depending on it
    skip, and a single warning summarizes how many sentinels were left
    unresolved.
    """
    clean_config_env.joinpath("settings.toml").write_text(SENTINEL_CREDENTIALS_SETTINGS)

    with pytest.warns(UserWarning) as caught:
        test_config = Config()

    # the keys are absent, not empty: an empty value would not behave
    # as a missing one for keys like candlepin.org
    with pytest.raises(KeyError):
        test_config.get("candlepin", "username")
    with pytest.raises(KeyError):
        test_config.get("candlepin", "password")
    assert test_config.is_external is False
    messages = [str(warning.message) for warning in caught]
    assert any("2 Vault sentinel value(s)" in message for message in messages)
    assert any("no Vault credentials" in message for message in messages)


def test_no_credentials_skip_external_candlepin(
    clean_config_env, pytester, monkeypatch
):
    """
    Without Vault credentials a configuration with sentinel credentials
    makes the external_candlepin fixture skip the tests, instead of
    failing them, with a warning that explains why and is visible in
    the output of a normal pytest run.
    """
    monkeypatch.setenv("PYTHONPATH", str(REPO_ROOT), prepend=os.pathsep)
    pytester.makefile(".toml", settings=SENTINEL_CREDENTIALS_SETTINGS)

    pytester.makepyfile(textwrap.dedent("""\
            def test_needs_external_candlepin(external_candlepin):
                # must not be executed: the fixture has to skip the test
                assert False
            """))
    result = pytester.runpytest_subprocess(
        # load the plugin explicitly also when the package is not
        # installed, disabling the entry point to avoid loading the
        # plugin twice when the package is installed
        "-p",
        "no:client-tools",
        "-p",
        "pytest_client_tools.plugin",
        "-rs",
    )
    result.assert_outcomes(skipped=1)
    result.stdout.fnmatch_lines(["*missing external candlepin*"])
    # the diagnostic is visible also in a normal run, without -s: the
    # warning raised while the session fixture loads the configuration
    # is shown in the warnings summary
    result.stdout.fnmatch_lines(["*Vault sentinel value(s)*treated as absent*"])


def test_warning_is_visible_in_a_normal_run(clean_config_env, pytester, monkeypatch):
    """
    The degradation warning is visible in the output of a default
    ``pytest -q`` run over a configuration with an unresolved sentinel:
    pytest prints the warnings raised during the setup of the session
    fixture in its warnings summary, also when every test skips.
    """
    monkeypatch.setenv("PYTHONPATH", str(REPO_ROOT), prepend=os.pathsep)
    pytester.makefile(".toml", settings=SENTINEL_CREDENTIALS_SETTINGS)

    pytester.makepyfile(textwrap.dedent("""\
            def test_needs_external_candlepin(external_candlepin):
                # must not be executed: the fixture has to skip the test
                assert False
            """))
    result = pytester.runpytest_subprocess(
        "-p",
        "no:client-tools",
        "-p",
        "pytest_client_tools.plugin",
        "-q",
    )
    result.assert_outcomes(skipped=1)
    result.stdout.fnmatch_lines(["*Vault sentinel value(s)*"])


@pytest.mark.parametrize(
    "sentinel, message",
    [
        (
            "@vault:apps/example/missing-secret:password",
            "cannot read Vault path 'apps/example/missing-secret': HTTP 404",
        ),
        (
            "@vault:apps/example/example-secret:missing",
            "key 'missing' not found at Vault path 'apps/example/example-secret'",
        ),
        (
            "@vault:apps/example/example-secret",
            "malformed Vault sentinel '@vault:apps/example/example-secret'",
        ),
    ],
)
def test_resolution_failure_sentinel_absent(
    clean_config_env, vault_env, sentinel, message
):
    """
    A sentinel that cannot be read makes the key absent, exactly as if
    it was never defined, with a warning naming the failed path and
    key, never the value.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "{0}"
            password = "{0}"
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """).format(sentinel))

    with pytest.warns(UserWarning) as caught:
        test_config = Config()

    with pytest.raises(KeyError):
        test_config.get("candlepin", "password")
    assert test_config.is_external is False
    messages = [str(warning.message) for warning in caught]
    assert any(message in warning for warning in messages)


def test_auth_failure_sentinel_absent(clean_config_env, vault_server, monkeypatch):
    """
    A failing AppRole login (wrong credentials) makes the sentinels
    absent, with a warning naming the failure.
    """
    monkeypatch.setenv(
        "VAULT_ADDR", "http://127.0.0.1:{}".format(vault_server.server_port)
    )
    monkeypatch.setenv("VAULT_ROLE_ID", "wrong-role-id")
    monkeypatch.setenv("VAULT_SECRET_ID", "wrong-secret-id")
    clean_config_env.joinpath("settings.toml").write_text(SENTINEL_CREDENTIALS_SETTINGS)

    with pytest.warns(UserWarning) as caught:
        test_config = Config()

    with pytest.raises(KeyError):
        test_config.get("candlepin", "password")
    assert test_config.is_external is False
    messages = [str(warning.message) for warning in caught]
    assert any(
        "Vault AppRole login failed: HTTP 400" in message for message in messages
    )


@pytest.mark.parametrize(
    "sentinel",
    [
        "@vault:apps/example/missing-secret:password",
        "@vault:apps/example/example-secret:missing",
        "@vault:apps/example/example-secret",
    ],
)
def test_strict_mode_raises_on_resolution_failure(
    clean_config_env, vault_env, monkeypatch, sentinel
):
    """
    In strict mode a sentinel that cannot be resolved raises an error
    instead of being treated as absent.
    """
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_VAULT_REQUIRED", "1")
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "{0}"
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """).format(sentinel))

    with pytest.raises(VaultError):
        Config()


def test_strict_mode_raises_on_auth_failure(
    clean_config_env, vault_server, monkeypatch
):
    """
    In strict mode a failing AppRole login raises an error instead of
    being treated as absent settings.
    """
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_VAULT_REQUIRED", "1")
    monkeypatch.setenv(
        "VAULT_ADDR", "http://127.0.0.1:{}".format(vault_server.server_port)
    )
    monkeypatch.setenv("VAULT_ROLE_ID", "wrong-role-id")
    monkeypatch.setenv("VAULT_SECRET_ID", "wrong-secret-id")
    clean_config_env.joinpath("settings.toml").write_text(SENTINEL_SETTINGS)

    with pytest.raises(VaultError):
        Config()


def test_static_token_authentication(clean_config_env, vault_server, monkeypatch):
    """
    VAULT_TOKEN is an alternative to the AppRole: the sentinels are
    resolved with the static token, without any login request.
    """
    monkeypatch.setenv(
        "VAULT_ADDR", "http://127.0.0.1:{}".format(vault_server.server_port)
    )
    monkeypatch.setenv("VAULT_TOKEN", DUMMY_TOKEN)
    clean_config_env.joinpath("settings.toml").write_text(SENTINEL_SETTINGS)

    test_config = Config()

    assert test_config.get("candlepin", "password") == "dummy-vault-password"
    assert test_config.is_external is True


def test_sentinel_in_secrets_file_overrides_settings(clean_config_env, vault_env):
    """
    A sentinel in .secrets.toml overrides the plain value of
    settings.toml, for scalar and list values alike: the layers keep
    their precedence, and the list still replaces (instead of being
    concatenated with) the lower layer one.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "file-password"
            activation_keys = ["settings-key"]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    clean_config_env.joinpath(".secrets.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            password = "@vault:apps/example/secrets-secret:password"
            activation_keys = ["@vault:apps/example/secrets-secret:key"]
            """))

    test_config = Config()

    assert test_config.get("candlepin", "password") == "dummy-secrets-vault-password"
    # exactly the value of the highest layer, with no leftovers
    assert test_config.get("candlepin", "activation_keys") == [
        "dummy-secrets-vault-key"
    ]
    # the sibling keys still come from settings.toml
    assert test_config.get("candlepin", "username") == "dummy-username"
    assert test_config.is_external is True


def test_sentinel_in_env_var_resolved(clean_config_env, vault_env, monkeypatch):
    """
    A sentinel provided through a PYTEST_CLIENT_TOOLS_* environment
    variable is resolved like one coming from a settings file.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    monkeypatch.setenv(
        "PYTEST_CLIENT_TOOLS_CANDLEPIN__PASSWORD",
        "@vault:apps/example/example-secret:password",
    )

    test_config = Config()

    assert test_config.get("candlepin", "password") == "dummy-vault-password"
    assert test_config.is_external is True


def test_unresolved_list_element_makes_list_absent(clean_config_env, vault_env):
    """
    A list holding an unresolved sentinel is absent as a whole: a
    partially-resolved list must never be used.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "dummy-password"
            activation_keys = ["dummy-key-1", "@vault:apps/example/missing-secret:key"]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))

    with pytest.warns(UserWarning) as caught:
        test_config = Config()

    # the key is removed, exactly as if the file never defined it
    assert test_config._settings.get("candlepin.activation_keys") is None
    # the plain credentials still make the external Candlepin usable
    assert test_config.is_external is True
    messages = [str(warning.message) for warning in caught]
    assert any(
        "cannot read Vault path 'apps/example/missing-secret': HTTP 404" in message
        for message in messages
    )


def test_mixed_sentinel_and_plain_values(clean_config_env, vault_env):
    """
    A settings file can mix sentinel and plain values: only the
    sentinel ones are resolved, without touching the others.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "@vault:apps/example/example-secret:username"
            password = "@vault:apps/example/example-secret:password"
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))

    test_config = Config()

    assert test_config.get("candlepin", "username") == "dummy-vault-username"
    assert test_config.get("candlepin", "password") == "dummy-vault-password"
    assert test_config.get("candlepin", "org") == "dummy-org"
    assert test_config.get("candlepin", "port") == 8443
    assert test_config.is_external is True


# a full, valid external Candlepin configuration whose password is a
# sentinel, for the tests of the precedence of the environment
# variables over the file sentinels
def _write_sentinel_password_settings(directory, sentinel):
    directory.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "{0}"
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """).format(sentinel))


def test_env_var_wins_over_file_sentinel(clean_config_env, vault_env, monkeypatch):
    """
    An explicitly-set environment variable wins over a file sentinel
    for the same scalar key: the sentinel of the lower layer is not
    resolved at all, and never overwrites the environment variable
    value — not even when the section is rewritten to resolve the
    sentinel of a sibling key. This also holds on dynaconf 3.1.5,
    whose settings store keeps case-variant spellings of the same key
    next to each other: walking them must use the effective
    (dotted-read) value only.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "@vault:apps/example/example-secret:username"
            password = "@vault:apps/example/example-secret:password"
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__PASSWORD", "env-password")

    test_config = Config()

    assert test_config.get("candlepin", "password") == "env-password"
    # the sentinel of the sibling key is resolved as usual
    assert test_config.get("candlepin", "username") == "dummy-vault-username"
    assert test_config.is_external is True
    # the section rewrite leaves a single spelling of each key, and the
    # one of the password holds the value of the environment variable
    section = test_config._settings.as_dict()["CANDLEPIN"]
    assert section["PASSWORD"] == "env-password"
    assert "password" not in section
    assert section["USERNAME"] == "dummy-vault-username"
    assert "username" not in section


def test_env_var_wins_over_file_sentinel_without_credentials(
    clean_config_env, monkeypatch, recwarn
):
    """
    Without Vault credentials an environment variable still wins over
    a file sentinel for the same scalar key: the unresolved sentinel
    must never degrade the explicitly-set value to an empty one.
    """
    _write_sentinel_password_settings(
        clean_config_env, "@vault:apps/example/example-secret:password"
    )
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__PASSWORD", "env-password")

    test_config = Config()

    assert test_config.get("candlepin", "password") == "env-password"
    assert test_config.is_external is True
    # the sentinel is shadowed by the environment variable: the
    # effective settings hold no sentinel to warn about
    assert not [
        warning for warning in recwarn if "Vault sentinel" in str(warning.message)
    ]


def test_env_var_wins_over_failing_file_sentinel(
    clean_config_env, vault_env, monkeypatch, recwarn
):
    """
    An environment variable wins over a file sentinel that would fail
    to resolve (a missing Vault path): the failed read of the shadowed
    sentinel is not even attempted.
    """
    _write_sentinel_password_settings(
        clean_config_env, "@vault:apps/example/missing-secret:password"
    )
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__PASSWORD", "env-password")

    test_config = Config()

    assert test_config.get("candlepin", "password") == "env-password"
    assert test_config.is_external is True
    assert not [
        warning
        for warning in recwarn
        if "cannot read Vault path" in str(warning.message)
    ]


def test_strict_mode_raises_without_credentials(clean_config_env, monkeypatch):
    """
    In strict mode, sentinels left unresolved by the absence of Vault
    credentials raise an error: the most common way for Vault to be
    unavailable in an automated run is that the secret delivery
    mechanism failed to provide the credentials, and strict mode
    exists to fail loudly exactly then.
    """
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_VAULT_REQUIRED", "1")
    clean_config_env.joinpath("settings.toml").write_text(SENTINEL_SETTINGS)

    with pytest.raises(VaultError):
        Config()


def test_credentials_without_vault_addr_are_an_error(clean_config_env, monkeypatch):
    """
    Vault credentials without VAULT_ADDR fail the resolution: there is
    no default address (the resolver must never contact a server the
    user did not configure), so the sentinels are treated as absent,
    with a warning, and no network request is attempted.
    """

    def no_request(*args, **kwargs):
        raise AssertionError("no request must be attempted without VAULT_ADDR")

    monkeypatch.setattr("requests.get", no_request)
    monkeypatch.setattr("requests.post", no_request)
    monkeypatch.setenv("VAULT_TOKEN", DUMMY_TOKEN)
    clean_config_env.joinpath("settings.toml").write_text(SENTINEL_CREDENTIALS_SETTINGS)

    with pytest.warns(UserWarning) as caught:
        test_config = Config()

    with pytest.raises(KeyError):
        test_config.get("candlepin", "password")
    assert test_config.is_external is False
    messages = [str(warning.message) for warning in caught]
    assert any("VAULT_ADDR" in message for message in messages)


def test_strict_mode_raises_on_missing_vault_addr(clean_config_env, monkeypatch):
    """
    In strict mode, credentials without VAULT_ADDR raise an error
    instead of being treated as absent settings.
    """
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_VAULT_REQUIRED", "1")
    monkeypatch.setenv("VAULT_TOKEN", DUMMY_TOKEN)
    clean_config_env.joinpath("settings.toml").write_text(SENTINEL_SETTINGS)

    with pytest.raises(VaultError):
        Config()


# a full, valid external Candlepin configuration with plain
# credentials, whose extra keys hold sentinels nested in lists and in
# dictionaries nested in lists
NESTED_SENTINEL_SETTINGS = textwrap.dedent("""\
    [default.candlepin]
    host = "candlepin.example.test"
    port = 8443
    prefix = "/candlepin"
    insecure = false
    username = "dummy-username"
    password = "dummy-password"
    extra_nested = [["plain-element"], ["@vault:apps/example/example-secret:key"]]
    extra_dicts = [{ password = "@vault:apps/example/example-secret:password" }]
    org = "dummy-org"
    environments = ["dummy-env-1"]

    [default.insights]
    legacy_upload = false
    auto_update = false
    """)


def test_sentinels_nested_in_lists_resolved(clean_config_env, vault_env):
    """
    Sentinels nested in lists, and in dictionaries nested in lists,
    are resolved element-wise like the scalar elements of a list, with
    a single spelling of the keys in the section.
    """
    clean_config_env.joinpath("settings.toml").write_text(NESTED_SENTINEL_SETTINGS)

    test_config = Config()

    assert test_config.get("candlepin", "extra_nested") == [
        ["plain-element"],
        ["dummy-vault-key"],
    ]
    extra_dicts = test_config.get("candlepin", "extra_dicts")
    assert len(extra_dicts) == 1
    assert extra_dicts[0]["password"] == "dummy-vault-password"
    # the plain keys are untouched, and a single spelling of each key
    # is left in the section
    assert test_config.get("candlepin", "password") == "dummy-password"
    section = test_config._settings.as_dict()["CANDLEPIN"]
    assert section["EXTRA_NESTED"] == [["plain-element"], ["dummy-vault-key"]]
    assert "extra_nested" not in section


def test_nested_list_sentinel_removed_without_credentials(clean_config_env):
    """
    Without Vault credentials a sentinel nested in a list removes the
    containing list, exactly like a scalar sentinel element, and the
    warning counts it: the literal sentinel string never remains as
    the value.
    """
    clean_config_env.joinpath("settings.toml").write_text(NESTED_SENTINEL_SETTINGS)

    with pytest.warns(UserWarning) as caught:
        test_config = Config()

    assert test_config._settings.get("candlepin.extra_nested") is None
    assert test_config._settings.get("candlepin.extra_dicts") is None
    # the plain keys are untouched
    assert test_config.get("candlepin", "password") == "dummy-password"
    assert test_config.is_external is True
    messages = [str(warning.message) for warning in caught]
    # each sentinel is counted once, also when nested
    assert any("2 Vault sentinel value(s)" in message for message in messages)
    assert any("no Vault credentials" in message for message in messages)


def test_dict_in_list_sentinel_removed_without_credentials(clean_config_env):
    """
    Without Vault credentials a sentinel inside a dictionary nested in
    a list removes the containing list, like any other list sentinel,
    and the warning counts it.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "dummy-password"
            extra_dicts = [{ password = "@vault:apps/example/example-secret:password" }]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))

    with pytest.warns(UserWarning) as caught:
        test_config = Config()

    assert test_config._settings.get("candlepin.extra_dicts") is None
    assert test_config.get("candlepin", "password") == "dummy-password"
    messages = [str(warning.message) for warning in caught]
    assert any("1 Vault sentinel value(s)" in message for message in messages)


def test_nested_list_sentinel_removed_on_failed_read(clean_config_env, vault_env):
    """
    A sentinel nested in a list that cannot be read removes the
    containing list, with a warning naming the failed path.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "dummy-password"
            extra_nested = [
                ["plain-element"],
                ["@vault:apps/example/missing-secret:key"],
            ]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))

    with pytest.warns(UserWarning) as caught:
        test_config = Config()

    assert test_config._settings.get("candlepin.extra_nested") is None
    messages = [str(warning.message) for warning in caught]
    assert any(
        "cannot read Vault path 'apps/example/missing-secret': HTTP 404" in message
        for message in messages
    )


def test_strict_mode_raises_on_unresolved_list_sentinel(
    clean_config_env, vault_env, monkeypatch
):
    """
    In strict mode a sentinel nested in a list that cannot be resolved
    raises an error, like an unresolved scalar sentinel.
    """
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_VAULT_REQUIRED", "1")
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "dummy-password"
            extra_nested = [
                ["plain-element"],
                ["@vault:apps/example/missing-secret:key"],
            ]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))

    with pytest.raises(VaultError):
        Config()


def _write_shadowed_list_sentinel_settings(directory):
    """
    A full, valid configuration whose [default] activation_keys holds
    a sentinel, replaced by a plain list in a higher layer.
    """
    directory.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "dummy-password"
            activation_keys = ["@vault:apps/example/example-secret:key"]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [stage.candlepin]
            activation_keys = ["plain-stage-key"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))


@pytest.mark.parametrize("replacement", ["stage", "env_var"])
@pytest.mark.parametrize("strict", [False, True])
def test_lower_layer_list_sentinel_is_not_resolved_when_replaced(
    clean_config_env, monkeypatch, recwarn, capsys, replacement, strict
):
    """
    A sentinel in a list-valued setting that a higher layer (the
    selected environment, or a PYTEST_CLIENT_TOOLS_* environment
    variable) replaces is not part of the effective configuration: it
    is never resolved, and never warned about or failed for — not even
    in strict mode, where a run whose effective configuration needs no
    Vault access at all must succeed.
    """
    _write_shadowed_list_sentinel_settings(clean_config_env)
    expected = ["plain-stage-key"]
    if replacement == "stage":
        monkeypatch.setenv("ENV_FOR_DYNACONF", "stage")
    else:
        expected = ["plain-env-key"]
        monkeypatch.setenv(
            "PYTEST_CLIENT_TOOLS_CANDLEPIN__ACTIVATION_KEYS", '["plain-env-key"]'
        )
    if strict:
        monkeypatch.setenv("PYTEST_CLIENT_TOOLS_VAULT_REQUIRED", "1")

    test_config = Config()

    assert test_config.get("candlepin", "activation_keys") == expected
    assert test_config.is_external is True
    # no Vault diagnostic at all, on any channel: the sentinel of the
    # replaced layer was never resolved
    assert not [warning for warning in recwarn if "Vault" in str(warning.message)]
    assert "Vault" not in capsys.readouterr().err


def _write_effective_list_sentinel_settings(directory):
    """
    A full, valid configuration with plain credentials whose effective
    activation_keys holds a sentinel.
    """
    directory.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "dummy-password"
            activation_keys = ["dummy-key-1", "@vault:apps/example/example-secret:key"]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))


def test_unresolved_effective_list_sentinel_without_credentials(
    clean_config_env,
):
    """
    The counterpart of the shadowing test: a sentinel in the effective
    list is resolved, and without credentials the list is absent as a
    whole, with the warning counting the sentinel.
    """
    _write_effective_list_sentinel_settings(clean_config_env)

    with pytest.warns(UserWarning) as caught:
        test_config = Config()

    assert test_config._settings.get("candlepin.activation_keys") is None
    assert test_config.get("candlepin", "password") == "dummy-password"
    assert test_config.is_external is True
    messages = [str(warning.message) for warning in caught]
    assert any("1 Vault sentinel value(s)" in message for message in messages)
    assert any("no Vault credentials" in message for message in messages)


def test_strict_mode_raises_on_unresolved_effective_list_sentinel(
    clean_config_env, monkeypatch
):
    """
    In strict mode a sentinel in the effective list that cannot be
    resolved raises, like any unresolved sentinel.
    """
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_VAULT_REQUIRED", "1")
    _write_effective_list_sentinel_settings(clean_config_env)

    with pytest.raises(VaultError):
        Config()


def test_unresolved_org_sentinel_is_not_external(clean_config_env):
    """
    An unresolved candlepin.org sentinel never leaves an empty org
    behind: the key is absent, exactly as if it was never defined, so
    the external Candlepin is not considered configured and the tests
    depending on it skip.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "@vault:apps/example/example-secret:username"
            password = "@vault:apps/example/example-secret:password"
            org = "@vault:apps/example/example-secret:key"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))

    with pytest.warns(UserWarning):
        test_config = Config()

    with pytest.raises(KeyError):
        test_config.get("candlepin", "org")
    assert test_config.is_external is False


def test_unresolved_org_sentinel_with_activation_keys_fails_validation(
    clean_config_env,
):
    """
    An unresolved candlepin.org sentinel with plain activation keys
    behaves exactly as a missing org: never an empty value handed to
    the external tests. With dynaconf>=3.2 the validation fails the
    load, loudly, like a plain missing key; on dynaconf 3.1.5 (where
    the org validator does not fire for a missing key either) the key
    is absent and the consumers see the same KeyError they see for a
    missing one.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "dummy-password"
            activation_keys = ["dummy-key"]
            org = "@vault:apps/example/example-secret:key"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))

    with pytest.warns(UserWarning):
        try:
            test_config = Config()
        except ValidationError:
            return

    with pytest.raises(KeyError):
        test_config.get("candlepin", "org")


def test_unresolved_base_url_sentinel_uses_the_default(clean_config_env):
    """
    An unresolved insights.base_url sentinel leaves the key absent, so
    the validator applies its documented default instead of an empty
    URL: the consumers never see '' (and never build '/inventory/v1').
    The same holds for insights.ca_path.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "dummy-password"
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            base_url = "@vault:apps/example/example-secret:key"
            ca_path = "@vault:apps/example/example-secret:key"
            """))

    with pytest.warns(UserWarning):
        test_config = Config()

    assert test_config.get("insights", "base_url") == (
        "https://cert-api.access.redhat.com/r/insights/platform"
    )
    assert test_config.get("insights", "ca_path") == (
        "/etc/insights-client/cert-api.access.redhat.com.pem"
    )


def test_unresolved_password_sentinel_does_not_become_an_empty_credential(
    clean_config_env,
):
    """
    The sharp edge of an empty fallback value: a configuration whose
    username and activation keys are plain and whose password is an
    unresolved sentinel must not load with an empty password — and run
    the external tests against a real Candlepin with it. The key is
    absent, so the same validation error a missing password causes is
    raised, loudly, exactly as for a value missing from the file.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            password = "@vault:apps/example/example-secret:password"
            activation_keys = ["dummy-key"]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))

    with pytest.warns(UserWarning):
        with pytest.raises(ValidationError, match="candlepin.password"):
            Config()


def test_failed_login_happens_once_for_many_sentinels(
    clean_config_env, vault_server, monkeypatch
):
    """
    A failed AppRole login is a property of the credentials, not of
    the individual sentinel: the login is attempted at most once per
    run, however many sentinels the configuration holds.
    """
    monkeypatch.setenv(
        "VAULT_ADDR", "http://127.0.0.1:{}".format(vault_server.server_port)
    )
    monkeypatch.setenv("VAULT_ROLE_ID", "wrong-role-id")
    monkeypatch.setenv("VAULT_SECRET_ID", "wrong-secret-id")
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "@vault:apps/example/example-secret:username"
            password = "@vault:apps/example/example-secret:password"
            org = "@vault:apps/example/example-secret:key"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    vault_server.requests = []

    with pytest.warns(UserWarning):
        test_config = Config()

    logins = [
        path
        for method, path in vault_server.requests
        if path == "/v1/auth/approle/login"
    ]
    assert logins == ["/v1/auth/approle/login"]
    with pytest.raises(KeyError):
        test_config.get("candlepin", "password")


def test_request_timeout_happens_once_for_many_sentinels(clean_config_env, monkeypatch):
    """
    A connection-level failure is a property of the server, not of
    the individual sentinel: the request timeout is paid at most once
    per run, however many sentinels fail.
    """
    attempts = []

    def no_answer(url, **kwargs):
        attempts.append(url)
        raise requests.exceptions.ReadTimeout()

    monkeypatch.setattr("requests.get", no_answer)
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:1")
    monkeypatch.setenv("VAULT_TOKEN", DUMMY_TOKEN)
    clean_config_env.joinpath("settings.toml").write_text(SENTINEL_CREDENTIALS_SETTINGS)

    with pytest.warns(UserWarning):
        test_config = Config()

    assert attempts == ["http://127.0.0.1:1/v1/apps/data/example/example-secret"]
    with pytest.raises(KeyError):
        test_config.get("candlepin", "password")


@pytest.mark.parametrize(
    "exception, name",
    [
        (requests.exceptions.ReadTimeout(), "ReadTimeout"),
        (requests.exceptions.ConnectionError(), "ConnectionError"),
    ],
)
def test_request_timeout_is_reported(clean_config_env, monkeypatch, exception, name):
    """
    A requests-level failure of the read is reported as a VaultError
    naming the class of the exception only (the message of a requests
    exception can embed the address of the server).
    """

    def no_answer(url, **kwargs):
        raise exception

    monkeypatch.setattr("requests.get", no_answer)
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:1")
    monkeypatch.setenv("VAULT_TOKEN", DUMMY_TOKEN)
    resolver = VaultResolver()

    with pytest.raises(VaultError) as caught:
        resolver.resolve("@vault:apps/example/example-secret:key")

    assert str(caught.value) == (
        "cannot read Vault path 'apps/example/example-secret': {0}".format(name)
    )


class _FakeResponse:
    """
    A stand-in for a ``requests`` response, for the tests of the
    handling of the answers of the Vault server.
    """

    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self.headers = {}
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("malformed JSON")
        return self._payload


@pytest.mark.parametrize(
    "response, message",
    [
        (
            _FakeResponse(403),
            "cannot read Vault path 'apps/example/example-secret': HTTP 403",
        ),
        (
            _FakeResponse(500),
            "cannot read Vault path 'apps/example/example-secret': HTTP 500",
        ),
        (
            _FakeResponse(200),
            "malformed Vault response for path 'apps/example/example-secret'",
        ),
        (
            _FakeResponse(200, {"data": {"data": {"key": 42}}}),
            "the value of key 'key' at Vault path 'apps/example/example-secret'"
            " is not a string",
        ),
    ],
)
def test_http_error_is_reported(clean_config_env, monkeypatch, response, message):
    """
    An error or unusable answer of the Vault server is reported as a
    VaultError naming the path and the key involved, never the value.
    """
    monkeypatch.setattr("requests.get", lambda url, **kwargs: response)
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:1")
    monkeypatch.setenv("VAULT_TOKEN", DUMMY_TOKEN)
    resolver = VaultResolver()

    with pytest.raises(VaultError) as caught:
        resolver.resolve("@vault:apps/example/example-secret:key")

    assert message in str(caught.value)


def test_skip_verify_is_passed_to_the_request(clean_config_env, monkeypatch):
    """
    VAULT_SKIP_VERIFY reaches the verify= argument of the actual
    request, together with the request timeout and the token header.
    """
    calls = []
    response = _FakeResponse(200, {"data": {"data": {"key": "dummy-value"}}})

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return response

    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example.test:8200")
    monkeypatch.setenv("VAULT_TOKEN", DUMMY_TOKEN)
    monkeypatch.setenv("VAULT_SKIP_VERIFY", "1")
    resolver = VaultResolver()

    assert resolver.resolve("@vault:apps/example/example-secret:key") == "dummy-value"
    assert len(calls) == 1
    url, kwargs = calls[0]
    assert url == "https://vault.example.test:8200/v1/apps/data/example/example-secret"
    assert kwargs["verify"] is False
    assert kwargs["timeout"] == REQUEST_TIMEOUT
    assert kwargs["allow_redirects"] is False
    assert kwargs["headers"]["X-Vault-Token"] == DUMMY_TOKEN


def test_cross_host_redirect_does_not_receive_the_token(clean_config_env, monkeypatch):
    """
    A redirect to a host other than the one of VAULT_ADDR is refused
    with an error naming the target: the request is never sent to it,
    so the target never sees the X-Vault-Token header.
    """
    with _running(_make_vault_server()) as target, _running(
        _make_vault_server()
    ) as redirector:
        redirector.redirects = {
            "/v1/apps/data/example/example-secret": (
                "http://127.0.0.1:{0}/v1/apps/data/example/example-secret".format(
                    target.server_port
                )
            )
        }
        monkeypatch.setenv(
            "VAULT_ADDR",
            "http://127.0.0.1:{0}".format(redirector.server_port),
        )
        monkeypatch.setenv("VAULT_TOKEN", DUMMY_TOKEN)
        clean_config_env.joinpath("settings.toml").write_text(
            SENTINEL_CREDENTIALS_SETTINGS
        )

        with pytest.warns(UserWarning) as caught:
            test_config = Config()

        with pytest.raises(KeyError):
            test_config.get("candlepin", "password")
        messages = [str(warning.message) for warning in caught]
        assert any("different origin" in message for message in messages)
        # the redirect target was never contacted, so it never saw
        # the client token
        assert target.requests == []


def test_same_origin_redirect_is_followed(clean_config_env, vault_env, vault_server):
    """
    A redirect that stays on the origin of VAULT_ADDR (for example a
    Vault HA cluster redirecting to another path of the same server)
    keeps working: the read is re-issued to the new location, with the
    token.
    """
    vault_server.redirects = {
        "/v1/apps/data/example/example-secret": ("/v1/apps/data/example/secrets-secret")
    }
    try:
        clean_config_env.joinpath("settings.toml").write_text(SENTINEL_SETTINGS)

        test_config = Config()

        assert test_config.get("candlepin", "password") == (
            "dummy-secrets-vault-password"
        )
        assert test_config.is_external is True
    finally:
        vault_server.redirects = {}


def test_login_timeout_is_reported_and_attempted_once(clean_config_env, monkeypatch):
    """
    A connection-level failure of the AppRole login is reported as a
    VaultError naming the class of the exception only, and the login
    is attempted at most once however many sentinels are resolved.
    """
    attempts = []

    def no_answer(url, **kwargs):
        attempts.append(url)
        raise requests.exceptions.ReadTimeout()

    monkeypatch.setattr("requests.post", no_answer)
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:1")
    monkeypatch.setenv("VAULT_ROLE_ID", DUMMY_ROLE_ID)
    monkeypatch.setenv("VAULT_SECRET_ID", DUMMY_SECRET_ID)
    resolver = VaultResolver()

    for _ in range(2):
        with pytest.raises(VaultError) as caught:
            resolver.resolve("@vault:apps/example/example-secret:key")
        assert "Vault AppRole login failed: ReadTimeout" in str(caught.value)

    assert attempts == ["http://127.0.0.1:1/v1/auth/approle/login"]
