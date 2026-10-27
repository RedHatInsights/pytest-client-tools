# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT


import pytest
import requests

from pytest_client_tools import insights_client as insights_client_mod
from pytest_client_tools.insights_client import InsightsClient, InsightsClientConfig


def _patch_insights_client_config(monkeypatch, conf_file):
    monkeypatch.setattr(
        insights_client_mod,
        "InsightsClientConfig",
        lambda path="/etc/insights-client/insights-client.conf": InsightsClientConfig(
            str(conf_file)
        ),
    )


def test_config_not_existing(tmp_path):
    with pytest.raises(FileNotFoundError):
        InsightsClientConfig(str(tmp_path / "not-existing.conf"))


def test_config_missing_main_section(tmp_path):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text("""[foo]
authmethod=CERT
""")
    conf = InsightsClientConfig(conf_file)
    with pytest.raises(KeyError):
        assert conf.authmethod == "CERT"


def test_config_missing_key(tmp_path):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text("""[insights-client]
auto_config=True
""")
    conf = InsightsClientConfig(conf_file)
    with pytest.raises(KeyError):
        assert conf.authmethod == "CERT"


def test_config_existing_keys(tmp_path):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text("""[insights-client]
auto_config=True
authmethod=CERT
cmd_timeout=120
http_timeout=120
        """)
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
    conf_file.write_text("""[insights-client]
auto_config=True
authmethod=CERT
cmd_timeout=120
http_timeout=120
        """)
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
    conf_file.write_text("""[insights-client]
auto_config=True
""")
    conf = InsightsClientConfig(conf_file)
    assert conf.auto_config
    conf_file.write_text("""[insights-client]
auto_config=False
""")
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
    conf_file.write_text(f"""[insights-client]
cert_verify={key_value}
""")
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


def test_get_services_api_verify_prefers_constructor(tmp_path, monkeypatch):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text("[insights-client]\ncert_verify=True\n")
    _patch_insights_client_config(monkeypatch, conf_file)
    client = InsightsClient(services_api_verify="/etc/rhsm/ca/katello-server-ca.pem")
    assert client.get_services_api_verify() == "/etc/rhsm/ca/katello-server-ca.pem"


def test_get_services_api_verify_falls_back_to_config(tmp_path, monkeypatch):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text("[insights-client]\ncert_verify=/from-config.pem\n")
    _patch_insights_client_config(monkeypatch, conf_file)
    client = InsightsClient()
    assert client.get_services_api_verify() == "/from-config.pem"


def test_get_services_api_verify_defaults_true(tmp_path, monkeypatch):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text("[insights-client]\n")
    _patch_insights_client_config(monkeypatch, conf_file)
    client = InsightsClient()
    assert client.get_services_api_verify() is True


def _inventory_client(tmp_path, monkeypatch):
    conf_file = tmp_path / "file.conf"
    conf_file.write_text("[insights-client]\n")
    _patch_insights_client_config(monkeypatch, conf_file)
    monkeypatch.setattr(InsightsClient, "uuid", "00000000-0000-0000-0000-000000000000")
    monkeypatch.setattr(
        InsightsClient,
        "get_services_api_base_url",
        lambda self: "https://cert.cloud.redhat.com/api",
    )
    return InsightsClient()


def test_get_inventory_id_skips_on_ssl_error(tmp_path, monkeypatch):
    client = _inventory_client(tmp_path, monkeypatch)

    def _ssl(*args, **kwargs):
        raise requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED")

    monkeypatch.setattr(insights_client_mod.requests, "get", _ssl)
    with pytest.raises(pytest.skip.Exception, match="TLS verification failed"):
        client._get_inventory_id()


def test_get_inventory_id_skips_on_http_400_on_satellite(tmp_path, monkeypatch):
    monkeypatch.setenv("ENV_FOR_DYNACONF", "satellite619")
    client = _inventory_client(tmp_path, monkeypatch)

    class _Resp:
        status_code = 400

    monkeypatch.setattr(
        insights_client_mod.requests, "get", lambda *args, **kwargs: _Resp()
    )
    with pytest.raises(pytest.skip.Exception, match="HTTP 400 on Satellite"):
        client._get_inventory_id()


def test_get_inventory_id_raises_on_http_400_on_cloud(tmp_path, monkeypatch):
    monkeypatch.setenv("ENV_FOR_DYNACONF", "prod")
    client = _inventory_client(tmp_path, monkeypatch)

    class _Resp:
        status_code = 400

        def raise_for_status(self):
            raise requests.exceptions.HTTPError("400")

    monkeypatch.setattr(
        insights_client_mod.requests, "get", lambda *args, **kwargs: _Resp()
    )
    with pytest.raises(requests.exceptions.HTTPError):
        client._get_inventory_id()


def test_get_inventory_id_raises_on_http_404(tmp_path, monkeypatch):
    client = _inventory_client(tmp_path, monkeypatch)

    class _Resp:
        status_code = 404

        def raise_for_status(self):
            raise requests.exceptions.HTTPError("404")

    monkeypatch.setattr(
        insights_client_mod.requests, "get", lambda *args, **kwargs: _Resp()
    )
    with pytest.raises(requests.exceptions.HTTPError):
        client._get_inventory_id()
