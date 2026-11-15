# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT


import os

import pytest

os.environ["PYTEST_CLIENT_TOOLS_DISABLE_SELINUX"] = "1"

pytest_plugins = "pytester"


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
