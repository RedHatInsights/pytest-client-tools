# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import contextlib
import datetime
import functools
import locale
import logging
import pathlib
import shutil
import subprocess
import time
import uuid

import pytest
import toml

from .candlepin import Candlepin, ping_candlepin
from .inventory import Inventory
from .insights_client import InsightsClient, INSIGHTS_CLIENT_FILES_TO_SAVE
from .logger import LOGGER
from .podman import Podman
from .subscription_manager import (
    SubscriptionManager,
    SUBMAN_FILES_TO_SAVE,
    stop_rhsmcertd,
)
from .rhc import Rhc, RHC_FILES_TO_SAVE
from .test_config import TestConfig
from .util import ClientToolsPluginData, NodeRunningData, logged_run


_MARKERS = {
    "candlepin": "tests requiring a self-deployed Candlepin",
    "external_candlepin": "tests requiring an externally deployed Candlepin",
    "any_candlepin": "tests requiring any type of Candlepin",
    "subman": "tests for subscription-manager",
    "insights_client": "tests for insights-client",
    "rhc": "tests for rhc",
    "external_inventory": "tests requiring an external Inventory service",
}
_CANDLEPIN_FIXTURES = {x for x in _MARKERS.keys() if "candlepin" in x}


def _save_and_archive(files, subdir):
    def decorator_wrapper(func):
        @functools.wraps(func)
        def function_wrapper(*args, **kwargs):
            request = kwargs["request"]
            running_data = None
            if request.scope == "session":
                running_data = pytest._client_tools.global_running_data
            else:
                running_data = pytest._client_tools.running_data[request.node.nodeid]
            assert running_data
            tmp_path = running_data.tmp_path
            artifacts_collector = running_data.artifacts
            backup_path = tmp_path / f"backup-{subdir}"
            backup_path.mkdir()
            for f in files:
                with contextlib.suppress(FileNotFoundError):
                    if f.remove_at_start:
                        shutil.move(str(f.path), str(backup_path))
                    else:
                        shutil.copy2(f.path, backup_path)
            yield from func(*args, **kwargs)
            for f in files:
                with contextlib.suppress(FileNotFoundError):
                    artifacts_collector.copy(f.path)
                with contextlib.suppress(FileNotFoundError):
                    shutil.move(str(backup_path / f.path.name), str(f.path))

        return function_wrapper

    return decorator_wrapper


def _create_candlepin_container():
    return Podman(
        image="ghcr.io/ptoscano/candlepin-unofficial:latest",
        hostname="candlepin.local",
        port_mappings=[[8443, 8443], [8080, 8080]],
    )


@pytest.fixture(scope="session")
def test_config(request):
    return TestConfig()


@pytest.fixture(scope="session")
def candlepin(request, tmp_path_factory):
    with contextlib.ExitStack() as stack:
        start_container = not request.config.getoption(
            "--candlepin-container-is-running"
        )
        initial_wait = 0
        verify = False
        if start_container:
            container = stack.enter_context(_create_candlepin_container())
            # candlepin takes a while to start
            initial_wait = 5
            ca_cert = str(tmp_path_factory.mktemp("candlepin") / "ca.crt")
            container.cp("$C:/etc/candlepin/certs/candlepin-ca.crt", ca_cert)
            verify = ca_cert
        candlepin = Candlepin(
            host="localhost",
            port=8443,
            prefix="/candlepin",
            insecure=True,
            verify=verify,
        )
        ping_candlepin(candlepin, initial_wait=initial_wait)
        yield candlepin


@pytest.fixture(scope="session")
def external_candlepin(test_config):
    if not test_config.is_external:
        pytest.skip("missing external candlepin")
    candlepin = Candlepin(
        host=test_config.get("candlepin", "host"),
        port=test_config.get("candlepin", "port"),
        prefix=test_config.get("candlepin", "prefix"),
        insecure=test_config.get("candlepin", "insecure"),
    )
    yield candlepin


@pytest.fixture(scope="session")
def any_candlepin(request, test_config):
    candlepin_fixture = "external_candlepin" if test_config.is_external else "candlepin"
    candlepin = request.getfixturevalue(candlepin_fixture)
    yield candlepin


@pytest.fixture
@_save_and_archive(files=SUBMAN_FILES_TO_SAVE, subdir="subman")
def save_subman_files(request):
    yield


def _subman_common(request):
    if request.fixturename:
        fixturenames = request.fixturenames
    else:
        fixturenames = request.node.fixturenames
    candlepin_fixture = next(
        (i for i in fixturenames if i in _CANDLEPIN_FIXTURES),
        None,
    )
    subman = SubscriptionManager()
    has_subman_session = (
        request.fixturename != "subman_session"
        and "subman_session" in request.fixturenames
    )
    if not has_subman_session:
        # TODO enable debug also for all the categories
        subman.config(
            logging_default_log_level="DEBUG",
        )
        if candlepin_fixture:
            candlepin = request.getfixturevalue(candlepin_fixture)
            subman.config(
                server_hostname=candlepin.host,
                server_port=candlepin.port,
                server_prefix=candlepin.prefix,
                server_insecure="1" if candlepin.insecure else "0",
            )
        else:
            subman.config(
                server_hostname="invalid-hostname-set-to-avoid-mistakes",
            )
    try:
        yield subman
    finally:
        if not has_subman_session:
            with contextlib.suppress(subprocess.SubprocessError):
                subman.unregister()
            stop_rhsmcertd()


@pytest.fixture
def subman(save_subman_files, request):
    yield from _subman_common(request)


@pytest.fixture(scope="session")
@_save_and_archive(files=SUBMAN_FILES_TO_SAVE, subdir="subman")
def save_subman_session_files(request):
    yield


@pytest.fixture(scope="session")
def subman_session(save_subman_session_files, request):
    yield from _subman_common(request)


@pytest.fixture
@_save_and_archive(files=INSIGHTS_CLIENT_FILES_TO_SAVE, subdir="insights-client")
def save_insights_client_files(request):
    yield


@pytest.fixture
def insights_client(save_insights_client_files, test_config):
    insights_client = InsightsClient()
    save_config = False
    with contextlib.suppress(KeyError):
        legacy_upload = test_config.get("insights.legacy_upload")
        if legacy_upload is not None:
            insights_client.config.legacy_upload = legacy_upload
        save_config = True
    with contextlib.suppress(KeyError):
        auto_update = test_config.get("insights.auto_update")
        if auto_update is not None:
            insights_client.config.auto_update = auto_update
        save_config = True
    if save_config:
        insights_client.config.save()
    try:
        yield insights_client
    finally:
        with contextlib.suppress(subprocess.SubprocessError):
            insights_client.unregister()


@pytest.fixture
@_save_and_archive(files=RHC_FILES_TO_SAVE, subdir="rhc")
def save_rhc_files(request):
    yield


@pytest.fixture
def rhc(save_rhc_files, test_config):
    rhc = Rhc()
    config_file = pathlib.Path("/etc/rhc/config.toml")
    try:
        config = toml.loads(config_file.read_text())
    except FileNotFoundError:
        # file not found, start from an empty config
        config = {}
    except toml.TomlDecodeError as e:
        LOGGER.warning(
            "cannot load %s as TOML (skipping customizations): %s", config_file, e
        )
    else:
        config["log-level"] = "trace"
        config_file.write_text(toml.dumps(config))
    try:
        yield rhc
    finally:
        with contextlib.suppress(subprocess.SubprocessError):
            rhc.disconnect()


@pytest.fixture(scope="session")
def external_inventory(request, test_config):
    external_candlepin = request.getfixturevalue("external_candlepin")
    if not external_candlepin:
        pytest.skip("missing 'external_candlepin' fixture")
    # get the CA path: if it is non-empty, then it means that
    # the specified path enforces the SSL validation
    verify = test_config.get("insights", "ca_path")
    if not verify:
        # empty/unset CA path: get whether verify the SSL connection
        # using the system CA store
        verify = not test_config.get("insights", "insecure")
    inventory = Inventory(
        base_url=test_config.get("insights", "base_url") + "/inventory/v1",
        verify=verify,
    )
    yield inventory


@pytest.fixture
def _init_inventory_from_insights_client(request):
    insights_client = request.getfixturevalue("insights_client")
    assert insights_client
    external_inventory = request.getfixturevalue("external_inventory")
    assert external_inventory
    external_inventory._insights_client = insights_client
    yield
    external_inventory._insights_client = None


def pytest_addoption(parser):
    group = parser.getgroup("client-tools")
    group.addoption(
        "--candlepin-container-is-running",
        action="store_true",
        help="the container of Candlepin is already running",
    )


def pytest_collection_modifyitems(config, items):
    for item in items:
        markers_to_add = set()
        item_markers = {m.name for m in item.own_markers}
        for fixture_name in item.fixturenames:
            if fixture_name not in _MARKERS:
                # fixture without associated marker, skip
                continue
            if fixture_name not in item_markers:
                markers_to_add.add(fixture_name)
        for marker in markers_to_add:
            item.add_marker(marker)
        if "rhc" in item.fixturenames:
            if "subman" not in item.fixturenames:
                item.fixturenames.append("subman")
            if "insights_client" not in item.fixturenames:
                item.fixturenames.append("insights_client")
        if (
            "insights_client" in item.fixturenames
            and "external_inventory" in item.fixturenames
        ):
            item.fixturenames.append("_init_inventory_from_insights_client")
        for jira_marker in item.iter_markers(name="jira"):
            for jira in jira_marker.args:
                jira_item = jira.lower()
                jira_item = jira_item.replace("-", "_")
                jira_item = "jira_" + jira_item
                item.add_marker(jira_item)
                config.addinivalue_line(
                    "markers", f"{jira_item}: test for jira card {jira}"
                )


def pytest_configure(config):
    for mark, description in _MARKERS.items():
        config.addinivalue_line("markers", f"{mark}: {description}")
    config.addinivalue_line("markers", "jira(id): test for jira cards")
    locale.setlocale(locale.LC_ALL, "C.UTF-8")
    pytest._client_tools = ClientToolsPluginData()


def pytest_runtestloop(session):
    # set the log level for our logger to the effective one set by pytest;
    # this cannot be done in pytest_configure(), as it is not set yet
    LOGGER.setLevel(logging.getLogger().getEffectiveLevel())


def pytest_runtest_protocol(item, nextitem):
    node_running_data = NodeRunningData(item)
    pytest._client_tools.running_data[item.nodeid] = node_running_data
    LOGGER.handlers.remove(pytest._client_tools.global_running_data.handler)
    logging.getLogger().addHandler(node_running_data.handler)
    if pytest._client_tools.log_selinux_audits:
        node_running_data.timestamp = datetime.datetime.now()


def pytest_runtest_logfinish(nodeid, location):
    node_running_data = pytest._client_tools.running_data.pop(nodeid)
    node_running_data.archive_test_log()
    if pytest._client_tools.log_selinux_audits:
        time.sleep(1)
        marker = f"pytest-client-tools-{uuid.uuid4()}"
        logged_run(
            ["auditctl", "-m", marker],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(1, 100):
            proc = logged_run(
                f"ausearch -i -m user | grep -q {marker}",
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True,
            )
            if proc.returncode == 0:
                break
            time.sleep(0.1)
        proc_ausearch = logged_run(
            [
                "ausearch",
                "-i",
                "-m",
                "avc",
                "-ts",
                node_running_data.timestamp.strftime("%x"),
                node_running_data.timestamp.strftime("%T"),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc_ausearch.returncode not in [0, 1]:
            proc_ausearch.check_returncode()
        if proc_ausearch.stdout:
            node_running_data.artifacts.write_text("selinux.log", proc_ausearch.stdout)
    logging.getLogger().handlers.remove(node_running_data.handler)
    LOGGER.addHandler(pytest._client_tools.global_running_data.handler)


def pytest_sessionfinish(session, exitstatus):
    pytest._client_tools.global_running_data.archive_test_log()
