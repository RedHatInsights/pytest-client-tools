# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import pathlib
from types import SimpleNamespace

from pytest_client_tools import plugin
from pytest_client_tools.util import ArtifactsCollector, SavedFile

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


class FakeInsightsClient:
    def __init__(self, stdout="", stderr=""):
        self._proc = SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)
        self.status_calls = []

    def run(self, *args, **kwargs):
        self.status_calls.append((args, kwargs))
        return self._proc


def test_registration_state_capture_survives_missing_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    # a test that ends registered: .unregistered does not exist, and its
    # absence must not abort the capture of machine-id nor the --status
    # snapshot
    (state / ".registered").write_text("")
    (state / "machine-id").write_text("c2ec2a44-6d64-445d-a632-8f33a2a9ad21")
    monkeypatch.setattr(
        plugin,
        "INSIGHTS_CLIENT_REGISTRATION_FILES",
        (
            SavedFile(state / ".registered"),
            SavedFile(state / ".unregistered"),
            SavedFile(state / "machine-id"),
        ),
    )

    client = FakeInsightsClient(stdout="This host is registered.\n")
    running_data = SimpleNamespace(artifacts=ArtifactsCollector(name="test"))

    plugin._archive_registration_state(client, running_data)

    archived = tmp_path / "artifacts" / "test"
    assert (archived / ".registered").exists()
    assert not (archived / ".unregistered").exists()
    assert (
        archived / "machine-id"
    ).read_text() == "c2ec2a44-6d64-445d-a632-8f33a2a9ad21"
    assert (archived / "insights-client-status.txt").read_text() == (
        "This host is registered.\n"
    )
    assert client.status_calls == [
        (("--status",), {"check": False, "selinux_context": None})
    ]


def test_save_and_archive_restores_files_not_in_archive_files(pytester, monkeypatch):
    """Files backed up but excluded from archive_files are still restored.

    They are captured earlier (e.g. the registration markers at test
    end); skipping their restore would leak the post-teardown state onto
    the host.
    """
    monkeypatch.setenv("PYTHONPATH", str(REPO_ROOT))
    pytester.makepyfile(test_save="""
        import pathlib

        import pytest

        from pytest_client_tools.plugin import _save_and_archive
        from pytest_client_tools.util import SavedFile

        @pytest.fixture
        @_save_and_archive(
            files=(SavedFile(pathlib.Path("kept")), SavedFile(pathlib.Path("early"))),
            subdir="sub",
            archive_files=(SavedFile(pathlib.Path("kept")),),
        )
        def save_files(request):
            yield

        pathlib.Path("kept").write_text("old-kept")
        pathlib.Path("early").write_text("old-early")

        def test_restore(save_files):
            pathlib.Path("kept").write_text("during-test")
            pathlib.Path("early").write_text("during-test")
        """)

    # run in a subprocess: an in-process run would replace the plugin
    # state (pytest._client_tools) of this very session
    result = pytester.runpytest_subprocess(
        "-q",
        # load the plugin explicitly also when the package is not
        # installed, disabling the entry point to avoid loading the plugin
        # twice when the package is installed
        "-p",
        "no:client-tools",
        "-p",
        "pytest_client_tools.plugin",
    )

    result.assert_outcomes(passed=1)
    # both files are restored to their pre-test content
    assert (pytester.path / "kept").read_text() == "old-kept"
    assert (pytester.path / "early").read_text() == "old-early"
    # only archive_files is archived at teardown
    bundle = pytester.path / "artifacts" / "test_save" / "test_restore"
    assert (bundle / "kept").exists()
    assert not (bundle / "early").exists()


def test_registration_state_capture_status_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    (state / ".unregistered").write_text("")
    monkeypatch.setattr(
        plugin,
        "INSIGHTS_CLIENT_REGISTRATION_FILES",
        (SavedFile(state / ".unregistered"),),
    )

    class BrokenInsightsClient:
        def run(self, *args, **kwargs):
            raise FileNotFoundError("insights-client vanished")

    running_data = SimpleNamespace(artifacts=ArtifactsCollector(name="test"))

    # a failing --status run must not raise: the markers are still archived
    plugin._archive_registration_state(BrokenInsightsClient(), running_data)

    archived = tmp_path / "artifacts" / "test"
    assert (archived / ".unregistered").exists()
    assert not (archived / "insights-client-status.txt").exists()
