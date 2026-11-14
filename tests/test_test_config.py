# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

"""
Tests for the Dynaconf-based test configuration.

These tests prove that the configuration is fully satisfiable from
environment variables only, with the settings files (settings.toml,
.secrets.toml) as an optional override.

All the credential-like values used here are dummy values.
"""

import os
import pathlib
import textwrap

import pytest

from pytest_client_tools.test_config import (
    LIST_SETTINGS_KEYS,
    TestConfig as Config,
)

# Root of the repository, used to make the plugin importable in subprocesses
# run by pytester also when the package is not installed.
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# A full, valid dummy configuration provided only via environment variables.
DUMMY_CANDLEPIN_ENV = {
    "PYTEST_CLIENT_TOOLS_CANDLEPIN__HOST": "candlepin.example.test",
    "PYTEST_CLIENT_TOOLS_CANDLEPIN__PORT": "8443",
    "PYTEST_CLIENT_TOOLS_CANDLEPIN__PREFIX": "/candlepin",
    "PYTEST_CLIENT_TOOLS_CANDLEPIN__INSECURE": "true",
    "PYTEST_CLIENT_TOOLS_CANDLEPIN__USERNAME": "dummy-username",
    "PYTEST_CLIENT_TOOLS_CANDLEPIN__PASSWORD": "dummy-password",
    "PYTEST_CLIENT_TOOLS_CANDLEPIN__ACTIVATION_KEYS": '["dummy-key-1"]',
    "PYTEST_CLIENT_TOOLS_CANDLEPIN__ORG": "dummy-org",
    "PYTEST_CLIENT_TOOLS_CANDLEPIN__ENVIRONMENTS": '["dummy-env-1"]',
    "PYTEST_CLIENT_TOOLS_INSIGHTS__LEGACY_UPLOAD": "false",
    "PYTEST_CLIENT_TOOLS_INSIGHTS__AUTO_UPDATE": "false",
}


@pytest.fixture
def clean_config_env(tmp_path, monkeypatch):
    """
    Isolate the configuration from the current environment: no
    configuration environment variable, no settings file pickable up from
    the cwd.
    """
    for name in list(os.environ):
        if name.startswith("PYTEST_CLIENT_TOOLS_"):
            if name == "PYTEST_CLIENT_TOOLS_DISABLE_SELINUX":
                # not read by the plugin from the Dynaconf settings, and
                # needed to keep the SELinux checks of the plugin disabled
                # while testing
                continue
            monkeypatch.delenv(name, raising=False)
        elif name.startswith("DYNACONF_") or name.endswith("_FOR_DYNACONF"):
            # the env vars of the default Dynaconf prefix, and the Dynaconf
            # options (ENV_FOR_DYNACONF, SETTINGS_FILE_FOR_DYNACONF, ...)
            # would inject values into the settings being tested
            monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_flat_key_from_env_var_only(clean_config_env, monkeypatch):
    """
    A flat (top level) key can be provided with an env var without any
    nesting separator.
    """
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_EXAMPLE_FLAT_KEY", "dummy-value")

    test_config = Config()

    assert test_config.get("example_flat_key") == "dummy-value"


def test_nested_keys_from_env_vars_only(clean_config_env, monkeypatch):
    """
    The whole configuration can be provided with env vars only, including
    nested keys such as candlepin.username.
    """
    for name, value in DUMMY_CANDLEPIN_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_RHC__SERVER", "dummy-rhc-server")

    test_config = Config()

    assert test_config.is_external is True
    assert test_config.get("candlepin", "host") == "candlepin.example.test"
    # numbers, booleans and lists are parsed from the env var values
    assert test_config.get("candlepin", "port") == 8443
    assert isinstance(test_config.get("candlepin", "port"), int)
    assert test_config.get("candlepin", "insecure") is True
    assert test_config.get("candlepin", "username") == "dummy-username"
    assert test_config.get("candlepin", "password") == "dummy-password"
    assert test_config.get("candlepin", "activation_keys") == ["dummy-key-1"]
    assert test_config.get("candlepin", "org") == "dummy-org"
    assert test_config.get("candlepin", "environments") == ["dummy-env-1"]
    assert test_config.get("insights", "legacy_upload") is False
    assert test_config.get("rhc", "server") == "dummy-rhc-server"


def test_numeric_org_from_env_var_is_string(clean_config_env, monkeypatch):
    """
    A candlepin.org value that looks like a number is still handled as a
    string, thanks to the cast in its validator.
    """
    for name, value in DUMMY_CANDLEPIN_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__ORG", "12345678")

    test_config = Config()

    assert test_config.get("candlepin", "org") == "12345678"


def test_numeric_org_is_string_across_environments(clean_config_env, monkeypatch):
    """
    A candlepin.org value that looks like a number is a string also when
    the key is defined in both [default] and the selected environment:
    the section those layouts share is rewritten to give the list-valued
    settings their replace semantics, and the rewrite must keep the
    string normalization of candlepin.org.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            username = "default-username"
            password = "dummy-password"
            activation_keys = ["default-key-1"]
            org = 87654321
            environments = ["default-env-1"]

            [stage.candlepin]
            activation_keys = ["stage-key-1"]
            org = 87654321
            environments = ["stage-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    monkeypatch.setenv("ENV_FOR_DYNACONF", "stage")

    test_config = Config()
    org = test_config.get("candlepin", "org")
    assert org == "87654321"
    assert isinstance(org, str)

    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__ORG", "11112222")
    test_config = Config()
    org = test_config.get("candlepin", "org")
    assert org == "11112222"
    assert isinstance(org, str)
    # the section view holds a single spelling of the key, with the
    # effective value
    section = test_config._settings.as_dict()["CANDLEPIN"]
    assert section["ORG"] == "11112222"
    assert "org" not in section


def test_env_var_list_replaces_file_value(clean_config_env, monkeypatch):
    """
    The env var of a list-valued key (e.g. candlepin.activation_keys)
    replaces the value from the settings file instead of being
    concatenated with it.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "file-username"
            password = "dummy-password"
            activation_keys = ["key-file-1", "key-file-2"]
            org = "dummy-org"
            environments = ["env-file-1", "env-file-2"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    monkeypatch.setenv(
        "PYTEST_CLIENT_TOOLS_CANDLEPIN__ACTIVATION_KEYS", '["key-env-1"]'
    )
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__ENVIRONMENTS", '["env-env-1"]')

    test_config = Config()

    # the env vars win, and exactly: no value from the file is left over
    assert test_config.get("candlepin", "activation_keys") == ["key-env-1"]
    assert test_config.get("candlepin", "environments") == ["env-env-1"]
    # the sibling keys still come from the file
    assert test_config.is_external is True
    assert test_config.get("candlepin", "host") == "candlepin.example.test"
    assert test_config.get("candlepin", "username") == "file-username"


def test_list_settings_replace_between_environments(clean_config_env, monkeypatch):
    """
    The value of a list-valued key of the selected environment replaces,
    and is not concatenated with, the value of the same key of [default]:
    rhc registers with candlepin.activation_keys[0], and mixing the keys
    of different environments would cause a silent credential mismatch
    against the Candlepin of the selected environment.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "default-username"
            password = "dummy-password"
            activation_keys = ["default-key-1"]
            org = "dummy-org"
            environments = ["default-env-1"]

            [stage.candlepin]
            activation_keys = ["stage-key-1"]
            environments = ["stage-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    monkeypatch.setenv("ENV_FOR_DYNACONF", "stage")

    test_config = Config()

    # the values of the selected environment replace the [default] ones,
    # and exactly: no value of any other layer is left over
    assert test_config.get("candlepin", "activation_keys") == ["stage-key-1"]
    assert test_config.get("candlepin", "activation_keys")[0] == "stage-key-1"
    assert test_config.get("candlepin", "environments") == ["stage-env-1"]
    assert test_config.get("candlepin", "environments")[0] == "stage-env-1"
    # the keys omitted by the selected environment keep the [default]
    # values (dict-like inheritance is preserved)
    assert test_config.is_external is True
    assert test_config.get("candlepin", "host") == "candlepin.example.test"
    assert test_config.get("candlepin", "username") == "default-username"


def test_list_env_var_replaces_value_across_environments(clean_config_env, monkeypatch):
    """
    The env var of a list-valued key replaces the merged file values when
    the key is defined in both [default] and the selected environment,
    and the env var of another key of the same section still wins over
    the files: the section rewrite that gives the list its replace
    semantics must not revert the other keys to their file values.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            username = "default-username"
            password = "dummy-password"
            activation_keys = ["default-key-1"]
            org = "dummy-org"
            environments = ["default-env-1"]

            [stage.candlepin]
            host = "candlepin.stage.test"
            activation_keys = ["stage-key-1"]
            environments = ["stage-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    monkeypatch.setenv("ENV_FOR_DYNACONF", "stage")
    monkeypatch.setenv(
        "PYTEST_CLIENT_TOOLS_CANDLEPIN__ACTIVATION_KEYS", '["env-key-1"]'
    )
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__HOST", "env.example.test")

    test_config = Config()

    # the env var list replaces every file value of the key, exactly
    assert test_config.get("candlepin", "activation_keys") == ["env-key-1"]
    # the list without an env var keeps the selected environment's value
    assert test_config.get("candlepin", "environments") == ["stage-env-1"]
    # the env var of the scalar key of the same section still wins, and
    # the sibling keys still come from the files
    assert test_config.get("candlepin", "host") == "env.example.test"
    assert test_config.get("candlepin", "username") == "default-username"
    assert test_config.is_external is True
    # the section view holds a single spelling of each key, with the
    # effective value: no stale case-variant copy is left behind
    section = test_config._settings.as_dict()["CANDLEPIN"]
    assert section["ACTIVATION_KEYS"] == ["env-key-1"]
    assert section["HOST"] == "env.example.test"
    assert "activation_keys" not in section
    assert "host" not in section


def test_list_settings_inherit_default_when_env_omits(clean_config_env, monkeypatch):
    """
    A list-valued key omitted by the selected environment keeps the value
    of [default].
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "default-username"
            password = "dummy-password"
            activation_keys = ["default-key-1"]
            org = "dummy-org"
            environments = ["default-env-1"]

            [stage.candlepin]
            host = "stage-candlepin.example.test"

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    monkeypatch.setenv("ENV_FOR_DYNACONF", "stage")

    test_config = Config()

    assert test_config.get("candlepin", "activation_keys") == ["default-key-1"]
    assert test_config.get("candlepin", "environments") == ["default-env-1"]
    # the keys overridden by the selected environment have its values
    assert test_config.get("candlepin", "host") == "stage-candlepin.example.test"


def test_list_settings_replace_between_files(clean_config_env):
    """
    The value of a list-valued key in .secrets.toml replaces the one in
    settings.toml for the same environment, instead of being concatenated
    with it.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "dummy-username"
            activation_keys = ["settings-key-1"]
            org = "dummy-org"
            environments = ["settings-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    clean_config_env.joinpath(".secrets.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            password = "dummy-password"
            activation_keys = ["secrets-key-1"]
            environments = ["secrets-env-1"]
            """))

    test_config = Config()

    # the values of .secrets.toml replace the settings.toml ones, and
    # exactly: no value of settings.toml is left over
    assert test_config.get("candlepin", "activation_keys") == ["secrets-key-1"]
    assert test_config.get("candlepin", "environments") == ["secrets-env-1"]
    # the sibling keys still come from both files
    assert test_config.is_external is True
    assert test_config.get("candlepin", "username") == "dummy-username"
    assert test_config.get("candlepin", "password") == "dummy-password"


def test_empty_host_env_var_is_treated_as_absent(clean_config_env, monkeypatch):
    """
    An empty (or whitespace-only) candlepin.host value, for example set
    through an empty env var, is treated as no host at all: the external
    Candlepin is not considered configured, and the tests depending on it
    are skipped instead of failing to connect to an empty hostname.
    """
    for name, value in DUMMY_CANDLEPIN_ENV.items():
        monkeypatch.setenv(name, value)

    for empty_host in ("", "   "):
        monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__HOST", empty_host)

        test_config = Config()

        assert test_config.is_external is False


@pytest.mark.parametrize("empty_value", ["", "   "])
def test_empty_config_env_vars_are_treated_as_unset(
    clean_config_env, monkeypatch, empty_value
):
    """
    An empty (or whitespace-only) PYTEST_CLIENT_TOOLS_* env var is treated
    as unset: it does not override with an empty value the one coming from
    the settings files.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "file-username"
            password = "dummy-password"
            activation_keys = ["file-key-1"]
            org = "dummy-org"
            environments = ["file-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__USERNAME", empty_value)
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__ACTIVATION_KEYS", empty_value)

    test_config = Config()

    assert test_config.get("candlepin", "username") == "file-username"
    assert test_config.get("candlepin", "activation_keys") == ["file-key-1"]


@pytest.mark.parametrize("empty_value", ["", "   "])
def test_empty_creds_env_vars_are_treated_as_absent(
    clean_config_env, monkeypatch, empty_value
):
    """
    Empty (or whitespace-only) candlepin.username/password values, for
    example set through empty env vars, are treated as no credentials at
    all: the external Candlepin is not considered configured, and the
    tests depending on it are skipped instead of failing to authenticate.
    """
    for name, value in DUMMY_CANDLEPIN_ENV.items():
        monkeypatch.setenv(name, value)
    # drop the activation keys, so that only the username/password pair
    # can make the external Candlepin configured
    monkeypatch.delenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__ACTIVATION_KEYS")
    monkeypatch.delenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__ORG")
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__USERNAME", empty_value)
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__PASSWORD", empty_value)

    test_config = Config()

    assert test_config.is_external is False


@pytest.mark.parametrize("empty_value", ["", "   "])
@pytest.mark.parametrize("empty_setting", ["username", "password"])
def test_empty_creds_in_files_are_treated_as_absent(
    clean_config_env, empty_value, empty_setting
):
    """
    An empty (or whitespace-only) candlepin.username/password value, for
    example an empty string in a settings file, is treated as no value at
    all: the external Candlepin is not considered configured, and the
    tests depending on it are skipped instead of failing to authenticate.
    """
    values = {
        "username": '"dummy-username"',
        "password": '"dummy-password"',
    }
    values[empty_setting] = '"{}"'.format(empty_value)
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = {username}
            password = {password}
            org = "dummy-org"

            [default.insights]
            legacy_upload = false
            auto_update = false
            """.format(**values)))

    test_config = Config()

    assert test_config.is_external is False


def test_env_var_wins_over_file_value(clean_config_env, monkeypatch):
    """
    An env var overrides the value from the settings file, without dropping
    the sibling keys of the same section.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "file-username"
            password = "dummy-password"
            activation_keys = ["dummy-key-1"]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    monkeypatch.setenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__USERNAME", "env-var-username")

    test_config = Config()

    assert test_config.is_external is True
    assert test_config.get("candlepin", "username") == "env-var-username"
    # sibling keys still come from the file
    assert test_config.get("candlepin", "host") == "candlepin.example.test"
    assert test_config.get("candlepin", "password") == "dummy-password"


def test_env_vars_apply_to_selected_environment(clean_config_env, monkeypatch):
    """
    Env var overrides work on the Dynaconf environment selected with
    ENV_FOR_DYNACONF, and do not change the values of the other environments.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default]

            [stage.candlepin]
            host = "stage-candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = true
            username = "stage-file-username"
            password = "dummy-password"
            activation_keys = ["dummy-key-1"]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [stage.insights]
            legacy_upload = false
            auto_update = false

            [prod.candlepin]
            host = "prod-candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            username = "prod-file-username"
            password = "dummy-password"
            activation_keys = ["dummy-key-1"]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [prod.insights]
            legacy_upload = false
            auto_update = false
            """))
    monkeypatch.setenv(
        "PYTEST_CLIENT_TOOLS_CANDLEPIN__HOST", "env-var-candlepin.example.test"
    )

    monkeypatch.setenv("ENV_FOR_DYNACONF", "stage")
    stage_config = Config()
    assert stage_config.environment == "stage"
    assert stage_config.is_external is True
    # the env var wins over the file value of the selected environment
    assert stage_config.get("candlepin", "host") == "env-var-candlepin.example.test"
    # other keys still come from the selected environment of the file
    assert stage_config.get("candlepin", "username") == "stage-file-username"

    monkeypatch.setenv("ENV_FOR_DYNACONF", "prod")
    prod_config = Config()
    assert prod_config.environment == "prod"
    assert prod_config.is_external is True
    assert prod_config.get("candlepin", "host") == "env-var-candlepin.example.test"
    assert prod_config.get("candlepin", "username") == "prod-file-username"

    # without the env var, each environment keeps its own file value
    monkeypatch.delenv("PYTEST_CLIENT_TOOLS_CANDLEPIN__HOST")
    monkeypatch.setenv("ENV_FOR_DYNACONF", "prod")
    prod_config_no_env = Config()
    assert prod_config_no_env.get("candlepin", "host") == "prod-candlepin.example.test"


def test_files_only_configuration_still_works(clean_config_env):
    """
    Backward compatibility: a configuration based only on the settings files
    keeps working, with the credentials in .secrets.toml.
    """
    clean_config_env.joinpath("settings.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            host = "candlepin.example.test"
            port = 8443
            prefix = "/candlepin"
            insecure = false
            activation_keys = ["dummy-key-1"]
            org = "dummy-org"
            environments = ["dummy-env-1"]

            [default.insights]
            legacy_upload = false
            auto_update = false
            """))
    clean_config_env.joinpath(".secrets.toml").write_text(textwrap.dedent("""\
            [default.candlepin]
            username = "dummy-username"
            password = "dummy-password"
            """))

    test_config = Config()

    assert test_config.is_external is True
    assert test_config.get("candlepin", "username") == "dummy-username"
    assert test_config.get("candlepin", "password") == "dummy-password"


def test_missing_creds_skip_external_candlepin(clean_config_env, pytester, monkeypatch):
    """
    Without any configuration (no env vars, no files) the external_candlepin
    fixture makes the tests skip, instead of failing.
    """
    monkeypatch.setenv("PYTHONPATH", str(REPO_ROOT), prepend=os.pathsep)

    pytester.makepyfile(textwrap.dedent("""\
            def test_needs_external_candlepin(external_candlepin):
                # must not be executed: the fixture has to skip the test
                assert False
            """))
    result = pytester.runpytest_subprocess(
        # load the plugin explicitly also when the package is not
        # installed, disabling the entry point to avoid loading the plugin
        # twice when the package is installed
        "-p",
        "no:client-tools",
        "-p",
        "pytest_client_tools.plugin",
        "-rs",
    )
    result.assert_outcomes(skipped=1)
    result.stdout.fnmatch_lines(["*missing external candlepin*"])


def test_list_settings_keys_cover_list_validators(clean_config_env):
    """
    Consistency: every settings key whose validator asserts a list value is
    in LIST_SETTINGS_KEYS, so that the list normalization gives its value
    the replace semantics.
    """
    test_config = Config()

    list_validated_keys = {
        name
        for validator in test_config._settings.validators
        for name in validator.names
        if validator.operations.get("is_type_of") is list
    }

    assert list_validated_keys == set(LIST_SETTINGS_KEYS)
