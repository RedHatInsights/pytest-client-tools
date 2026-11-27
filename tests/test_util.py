# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT


import logging
import sys
import time
from types import SimpleNamespace
from unittest.mock import call, patch

import pytest

from pytest_client_tools.util import (
    ArtifactsCollector,
    _git,
    _os_compose,
    _rpm_versions,
    _test_branch,
    _test_commit,
    logged_run,
    loop_until,
    redact_arguments,
)


def test_os_compose_prefers_build_id_over_pretty_name(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text(
        'NAME="Red Hat Enterprise Linux"\n'
        'VERSION="9.7 (Plow)"\n'
        'VERSION_ID="9.7"\n'
        'PRETTY_NAME="Red Hat Enterprise Linux 9.7 (Plow)"\n'
    )
    # PRETTY_NAME is identical across nightlies and is not a compose id
    assert _os_compose(os_release) == "9.7"

    os_release.write_text('PRETTY_NAME="Fedora Linux 45"\n' 'BUILD_ID="20261119.n.0"\n')
    assert _os_compose(os_release) == "20261119.n.0"

    os_release.write_text('PRETTY_NAME="Fedora Linux 45"\n')
    # PRETTY_NAME is not a compose identifier and is never used
    assert _os_compose(os_release) == "unknown"

    assert _os_compose(tmp_path / "missing") == "unknown"


def test_rpm_versions(monkeypatch):
    from pytest_client_tools import util

    def fake_logged_run(cmd, **kwargs):
        package = cmd[-1]
        if package == "insights-core":
            return SimpleNamespace(
                returncode=1,
                stdout="",
                stderr="package insights-core is not installed",
            )
        return SimpleNamespace(returncode=0, stdout=f"{package}-3.2.0-1.el9", stderr="")

    monkeypatch.setattr(util, "logged_run", fake_logged_run)

    assert _rpm_versions() == {
        "insights-client": "insights-client-3.2.0-1.el9",
        "insights-core": "not installed",
        "selinux-policy": "selinux-policy-3.2.0-1.el9",
    }


def test_test_branch_and_commit(monkeypatch):
    from pytest_client_tools import util

    for env_var in ("GIT_BRANCH", "BRANCH", "CHANGE_BRANCH", "GITHUB_HEAD_REF"):
        monkeypatch.delenv(env_var, raising=False)

    # detached checkout: no branch, but the commit is still recorded
    monkeypatch.setattr(
        util,
        "_git",
        lambda command: "HEAD" if "--abbrev-ref" in command else "abc1234",
    )
    assert _test_branch() == "unknown"
    assert _test_commit() == "abc1234"

    # CI environment variables win over the git checkout, also covering
    # sources without .git
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature-branch")
    assert _test_branch() == "feature-branch"
    monkeypatch.delenv("GITHUB_HEAD_REF")
    monkeypatch.setenv("CHANGE_BRANCH", "rhel-9.7")
    assert _test_branch() == "rhel-9.7"
    monkeypatch.delenv("CHANGE_BRANCH")

    # a real branch from the checkout
    monkeypatch.setattr(
        util, "_git", lambda command: "main" if "--abbrev-ref" in command else None
    )
    assert _test_branch() == "main"


def test_git_runs_in_tmt_tree(monkeypatch):
    from pytest_client_tools import util

    seen = {}

    def fake_logged_run(command, **kwargs):
        seen["command"] = command
        seen["cwd"] = kwargs.get("cwd")
        return SimpleNamespace(returncode=0, stdout="main\n", stderr="")

    monkeypatch.setattr(util, "logged_run", fake_logged_run)
    monkeypatch.setenv("TMT_TREE", "/tmp/tmt-tree")

    assert _git(["git", "rev-parse", "--abbrev-ref", "HEAD"]) == "main"
    assert seen["cwd"] == "/tmp/tmt-tree"

    # sources without .git: git fails, no value
    monkeypatch.setattr(
        util,
        "logged_run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=128, stdout="", stderr="fatal: not a git repository"
        ),
    )
    assert _git(["git", "rev-parse", "--short", "HEAD"]) is None


def test_logged_run_never_logs_the_environment(caplog):
    secret_env = {"VAULT_SECRET_ID": "hunter2"}
    with caplog.at_level(logging.DEBUG, logger="pytest_client_tools"):
        logged_run([sys.executable, "-c", "pass"], env=secret_env)

    debug_messages = [r.message for r in caplog.records]
    assert any(m.startswith("running") for m in debug_messages)
    assert not any("VAULT_SECRET_ID" in m or "hunter2" in m for m in debug_messages)


def test_artifacts_collector_first_capture_wins(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    collector = ArtifactsCollector(name="test")

    first = tmp_path / "first.txt"
    first.write_text("captured at test end")
    collector.copy(first)

    # the source is rewritten by a later teardown (e.g. the unregister)
    first.write_text("state after teardown")
    collector.copy(first)

    archived = tmp_path / "artifacts" / "test" / "first.txt"
    assert archived.read_text() == "captured at test end"


@pytest.mark.parametrize(
    "args,redact_list,expected_args",
    [
        ([], [], []),
        (["a"], [], ["a"]),
        (["a", "--foo", "foo"], [], ["a", "--foo", "foo"]),
        (["a", "--foo=foo"], [], ["a", "--foo=foo"]),
        (["a", "--foo"], ["--foo"], ["a", "--foo"]),
        (["a", "--foo", "foo"], ["--foo"], ["a", "--foo", "<redacted>"]),
        (["a", "--foo", "foo"], ["--bar"], ["a", "--foo", "foo"]),
        (["a", "--foo=foo"], ["--foo"], ["a", "--foo=<redacted>"]),
        (["a", "--foo=foo"], ["--bar"], ["a", "--foo=foo"]),
        (["a", "--foo", "foo"], ["--unused", "--foo"], ["a", "--foo", "<redacted>"]),
        (["a", "--foo", "foo"], ["--unused", "--bar"], ["a", "--foo", "foo"]),
        (["a", "--foo=foo"], ["--unused", "--foo"], ["a", "--foo=<redacted>"]),
        (["a", "--foo=foo"], ["--unused", "--bar"], ["a", "--foo=foo"]),
        (["a", "--foobar", "foo"], ["--foo"], ["a", "--foobar", "foo"]),
        (["a", "--foobar=foo"], ["--foo"], ["a", "--foobar=foo"]),
        (["a", "--foo-bar", "foo"], ["--foo"], ["a", "--foo-bar", "foo"]),
        (["a", "--foo-bar=foo"], ["--foo"], ["a", "--foo-bar=foo"]),
    ],
)
def test_redact_arguments(args, redact_list, expected_args):
    assert redact_arguments(args, redact_list) == expected_args


class TestLoopUntil:
    """Test cases for the loop_until function."""

    def test_loop_until_success_immediate(self):
        """Test that loop_until returns True when predicate succeeds immediately."""
        with patch("pytest_client_tools.util.time.sleep") as sleep:
            result = loop_until(lambda: True, poll_sec=0.1, timeout_sec=1)
        assert result is True
        sleep.assert_not_called()

    def test_loop_until_success_after_retries(self):
        """
        Test that loop_until returns True when predicate succeeds after some retries.
        """
        counter = 0

        def predicate():
            nonlocal counter
            counter += 1
            return counter >= 3

        with patch("pytest_client_tools.util.time.sleep") as sleep:
            result = loop_until(predicate, poll_sec=0.1, timeout_sec=2)

        assert result is True
        assert counter == 3
        assert sleep.call_args_list == [call(0.1), call(0.1)]

    def test_loop_until_timeout(self):
        """Test that loop_until returns False when predicate never succeeds."""
        counter = 0

        def predicate():
            nonlocal counter
            counter += 1
            return False

        start_time = time.time()
        result = loop_until(predicate, poll_sec=0.1, timeout_sec=0.5)
        elapsed_time = time.time() - start_time

        assert result is False
        # Should have been called multiple times
        assert counter > 1
        # Should respect the timeout
        assert elapsed_time >= 0.5
        assert elapsed_time < 1.0  # Should not exceed timeout significantly

    def test_loop_until_default_parameters(self):
        """Test loop_until with default parameters."""
        # This test uses a very short timeout to avoid long test execution
        result = loop_until(lambda: False, timeout_sec=0.1)
        assert result is False

    def test_loop_until_custom_poll_interval(self):
        """Test loop_until with custom polling interval."""
        counter = 0

        def predicate():
            nonlocal counter
            counter += 1
            return counter >= 2

        start_time = time.time()
        result = loop_until(predicate, poll_sec=0.2, timeout_sec=1)
        elapsed_time = time.time() - start_time

        assert result is True
        assert counter == 2
        # Should take at least one polling interval (0.2 seconds)
        assert elapsed_time >= 0.2

    def test_loop_until_predicate_exception(self):
        """Test that loop_until propagates exceptions from predicate."""

        def failing_predicate():
            raise ValueError("Test exception")

        with pytest.raises(ValueError, match="Test exception"):
            loop_until(failing_predicate, poll_sec=0.1, timeout_sec=0.5)

    def test_loop_until_zero_timeout(self):
        """Test loop_until behavior with zero timeout."""
        counter = 0

        def predicate():
            nonlocal counter
            counter += 1
            return False

        result = loop_until(predicate, poll_sec=0.1, timeout_sec=0)

        assert result is False
        # With zero timeout, the predicate should not be called
        # since the timeout condition fails immediately
        assert counter == 0

    def test_loop_until_realistic_scenario(self):
        """
        Test a realistic scenario similar to checking if insights-client is registered.
        """
        # Simulate a service that becomes "registered" after some time
        start_check_time = time.time()
        registration_delay = 0.3  # Service becomes ready after 0.3 seconds

        def is_service_ready():
            return time.time() - start_check_time >= registration_delay

        start_time = time.time()
        result = loop_until(is_service_ready, poll_sec=0.1, timeout_sec=1)
        elapsed_time = time.time() - start_time

        assert result is True
        # Should complete shortly after the registration delay
        assert elapsed_time >= registration_delay
        assert elapsed_time < registration_delay + 0.5
