# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT


import pytest
from unittest.mock import patch, MagicMock

from pytest_client_tools.insights_client import InsightsClientConfig, InsightsClient


def test_config_not_existing(tmp_path):
    with pytest.raises(FileNotFoundError):
        InsightsClientConfig(str(tmp_path / "not-existing.conf"))


def test_config_missing_main_section(tmp_path):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text(
        """[foo]
authmethod=CERT
"""
    )
    conf = InsightsClientConfig(conf_file)
    with pytest.raises(KeyError):
        assert conf.authmethod == "CERT"


def test_config_missing_key(tmp_path):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text(
        """[insights-client]
auto_config=True
"""
    )
    conf = InsightsClientConfig(conf_file)
    with pytest.raises(KeyError):
        assert conf.authmethod == "CERT"


def test_config_existing_keys(tmp_path):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text(
        """[insights-client]
auto_config=True
authmethod=CERT
cmd_timeout=120
http_timeout=120
        """
    )
    conf = InsightsClientConfig(conf_file)
    # bool
    assert conf.auto_config
    assert isinstance(conf.auto_config, bool)
    # string
    assert conf.authmethod == "CERT"
    assert isinstance(conf.authmethod, str)
    # int
    assert conf.cmd_timeout == 120
    assert isinstance(conf.cmd_timeout, int)
    # float
    assert conf.http_timeout == 120
    assert isinstance(conf.http_timeout, float)


def test_config_set_keys(tmp_path):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text(
        """[insights-client]
auto_config=True
authmethod=CERT
cmd_timeout=120
http_timeout=120
        """
    )
    conf = InsightsClientConfig(conf_file)
    # existing key
    conf.cmd_timeout = 60
    assert conf.cmd_timeout == 60
    # missing but known key
    with pytest.raises(KeyError):
        assert conf.loglevel == "DEBUG"
    conf.loglevel = "DEBUG"
    assert conf.loglevel == "DEBUG"
    # unknown key; setting will set a class attribute, not a config value
    conf.unknown = "see"
    assert conf.unknown == "see"
    # save and check the result
    conf.save()
    conf_file_text = conf_file.read_text()
    assert "cmd_timeout=60" in conf_file_text
    assert "loglevel=DEBUG" in conf_file_text
    assert "see" not in conf_file_text


def test_config_reload(tmp_path):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text(
        """[insights-client]
auto_config=True
"""
    )
    conf = InsightsClientConfig(conf_file)
    assert conf.auto_config
    conf_file.write_text(
        """[insights-client]
auto_config=False
"""
    )
    conf.reload()
    assert not conf.auto_config


@pytest.mark.parametrize(
    "key_value",
    [
        True,
        "/some/path",
    ],
)
def test_config_cert_verify_read(key_value, tmp_path):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text(
        f"""[insights-client]
cert_verify={key_value}
"""
    )
    conf = InsightsClientConfig(conf_file)
    assert isinstance(conf.cert_verify, type(key_value))
    assert conf.cert_verify == key_value


@pytest.mark.parametrize(
    "key_value",
    [
        True,
        "/some/path",
    ],
)
def test_config_cert_verify_write(key_value, tmp_path):
    conf_file = tmp_path / "file.conf"
    conf_file.touch()
    conf = InsightsClientConfig(conf_file)
    conf.cert_verify = key_value
    assert isinstance(conf.cert_verify, type(key_value))
    conf.save()
    conf_file_text = conf_file.read_text()
    assert f"cert_verify={key_value}" in conf_file_text


@patch("pytest_client_tools.insights_client._should_use_selinux_context")
@patch("pytest_client_tools.insights_client.InsightsClientConfig")
@patch("pytest_client_tools.insights_client.logged_run")
def test_insights_client_run_default_selinux_context(
    mock_logged_run, mock_config, mock_should_use
):
    """
    Test that InsightsClient.run uses default SELinux context
    on correct RHEL versions
    """
    mock_logged_run.return_value = MagicMock()
    mock_config.return_value = MagicMock()
    mock_should_use.return_value = True  # Simulate RHEL 9.7+/10.1+
    client = InsightsClient()

    client.run("--status")

    # Verify that runcon was called with the default context
    mock_logged_run.assert_called_once()
    called_args = mock_logged_run.call_args[0][0]
    assert called_args == [
        "runcon",
        "system_u:system_r:insights_client_t",
        "insights-client",
        "--status",
    ]


@patch("pytest_client_tools.insights_client._should_use_selinux_context")
@patch("pytest_client_tools.insights_client.InsightsClientConfig")
@patch("pytest_client_tools.insights_client.logged_run")
def test_insights_client_run_default_no_selinux_on_old_rhel(
    mock_logged_run, mock_config, mock_should_use
):
    """Test that InsightsClient.run skips runcon on older RHEL versions by default."""
    mock_logged_run.return_value = MagicMock()
    mock_config.return_value = MagicMock()
    mock_should_use.return_value = False  # Simulate older RHEL
    client = InsightsClient()

    client.run("--status")

    # Verify that runcon was NOT used
    mock_logged_run.assert_called_once()
    called_args = mock_logged_run.call_args[0][0]
    assert called_args == ["insights-client", "--status"]


@patch("pytest_client_tools.insights_client.InsightsClientConfig")
@patch("pytest_client_tools.insights_client.logged_run")
def test_insights_client_run_no_selinux_context(mock_logged_run, mock_config):
    """Test that InsightsClient.run skips runcon when selinux_context=None."""
    mock_logged_run.return_value = MagicMock()
    mock_config.return_value = MagicMock()
    client = InsightsClient()

    client.run("--status", selinux_context=None)

    # Verify that runcon was NOT used
    mock_logged_run.assert_called_once()
    called_args = mock_logged_run.call_args[0][0]
    assert called_args == ["insights-client", "--status"]


@patch("pytest_client_tools.insights_client.InsightsClientConfig")
@patch("pytest_client_tools.insights_client.logged_run")
def test_insights_client_run_custom_selinux_context(mock_logged_run, mock_config):
    """Test that InsightsClient.run uses custom SELinux context when provided."""
    mock_logged_run.return_value = MagicMock()
    mock_config.return_value = MagicMock()
    client = InsightsClient()

    client.run("--status", selinux_context="unconfined_u:unconfined_r:unconfined_t")

    # Verify that runcon was called with the custom context
    mock_logged_run.assert_called_once()
    called_args = mock_logged_run.call_args[0][0]
    assert called_args == [
        "runcon",
        "unconfined_u:unconfined_r:unconfined_t",
        "insights-client",
        "--status",
    ]


@patch("pytest_client_tools.insights_client._should_use_selinux_context")
@patch("pytest_client_tools.insights_client.InsightsClientConfig")
@patch("pytest_client_tools.insights_client.logged_run")
def test_insights_client_register_default_selinux_context(
    mock_logged_run, mock_config, mock_should_use
):
    """
    Test that InsightsClient.register uses default SELinux context
    on correct RHEL versions
    """
    mock_logged_run.return_value = MagicMock()
    mock_config.return_value = MagicMock()
    mock_should_use.return_value = True  # Simulate RHEL 9.7+/10.1+
    client = InsightsClient()

    client.register()

    # Verify that runcon was called with the default context
    mock_logged_run.assert_called_once()
    called_args = mock_logged_run.call_args[0][0]
    assert called_args == [
        "runcon",
        "system_u:system_r:insights_client_t",
        "insights-client",
        "--register",
    ]


@patch("pytest_client_tools.insights_client.InsightsClientConfig")
@patch("pytest_client_tools.insights_client.logged_run")
def test_insights_client_register_no_selinux_context(mock_logged_run, mock_config):
    """Test that InsightsClient.register skips runcon when selinux_context=None."""
    mock_logged_run.return_value = MagicMock()
    mock_config.return_value = MagicMock()
    client = InsightsClient()

    client.register(selinux_context=None)

    # Verify that runcon was NOT used
    mock_logged_run.assert_called_once()
    called_args = mock_logged_run.call_args[0][0]
    assert called_args == ["insights-client", "--register"]


@patch("pytest_client_tools.insights_client._should_use_selinux_context")
@patch("pytest_client_tools.insights_client.InsightsClientConfig")
@patch("pytest_client_tools.insights_client.logged_run")
def test_insights_client_unregister_default_selinux_context(
    mock_logged_run, mock_config, mock_should_use
):
    """
    Test that InsightsClient.unregister uses default SELinux context
    on correct RHEL versions
    """
    mock_logged_run.return_value = MagicMock()
    mock_config.return_value = MagicMock()
    mock_should_use.return_value = True  # Simulate RHEL 9.7+/10.1+
    client = InsightsClient()

    client.unregister()

    # Verify that runcon was called with the default context
    mock_logged_run.assert_called_once()
    called_args = mock_logged_run.call_args[0][0]
    assert called_args == [
        "runcon",
        "system_u:system_r:insights_client_t",
        "insights-client",
        "--unregister",
    ]


@patch("pytest_client_tools.insights_client.InsightsClientConfig")
@patch("pytest_client_tools.insights_client.logged_run")
def test_insights_client_unregister_no_selinux_context(mock_logged_run, mock_config):
    """Test that InsightsClient.unregister skips runcon when selinux_context=None."""
    mock_logged_run.return_value = MagicMock()
    mock_config.return_value = MagicMock()
    client = InsightsClient()

    client.unregister(selinux_context=None)

    # Verify that runcon was NOT used
    mock_logged_run.assert_called_once()
    called_args = mock_logged_run.call_args[0][0]
    assert called_args == ["insights-client", "--unregister"]


@patch("subprocess.run")
def test_should_use_selinux_context(mock_run):
    """Test that _should_use_selinux_context returns True when """
    """insights-core-selinux is installed"""
    mock_run.return_value.returncode = 0
    from pytest_client_tools.insights_client import _should_use_selinux_context

    assert _should_use_selinux_context() is True
    mock_run.assert_called_once_with(
        ["rpm", "-q", "insights-core-selinux"], check=False
    )


@patch("subprocess.run")
def test_should_not_use_selinux_context(mock_run):
    """Test that _should_use_selinux_context returns False when """
    """insights-core-selinux is not installed"""
    mock_run.return_value.returncode = 1
    from pytest_client_tools.insights_client import _should_use_selinux_context

    assert _should_use_selinux_context() is False
    mock_run.assert_called_once_with(
        ["rpm", "-q", "insights-core-selinux"], check=False
    )
