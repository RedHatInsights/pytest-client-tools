# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT


import os

import pytest

from pytest_client_tools.util import NodeRunningData

os.environ["PYTEST_CLIENT_TOOLS_DISABLE_SELINUX"] = "1"

# The plugin archives the log of every test that emits log records. For
# this repository's own tests that would create files outside the
# temporary directories; the archiving runs in a hook (after the test
# fixtures), so the no-op must be installed for the whole session rather
# than per-test.
NodeRunningData.archive_test_log = lambda self: None

pytest_plugins = "pytester"


@pytest.fixture(autouse=True)
def _archive_environment_metadata():
    """Override the plugin's environment metadata capture with a no-op.

    The plugin's own tests do not need the per-test environment metadata
    (it describes the environment, not the unit under test), and letting
    it run would create an artifacts/ entry for every test of this
    repository's suite. Note that running the tests in a temporary
    directory would not help: the plugin resolves the artifacts path
    from the current directory before any fixture runs.
    """
    yield


@pytest.fixture
def clean_config_env(tmp_path, monkeypatch):
    """
    Isolate the configuration from the current environment: no
    configuration environment variable, no Vault variable, no settings
    file pickable up from the cwd.
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
        elif name.startswith("VAULT_"):
            # the credentials of the Vault sentinel resolution must not
            # leak from the environment of whoever runs the tests
            monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path
