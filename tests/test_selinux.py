import logging
from datetime import datetime
from types import SimpleNamespace

import pytest

from pytest_client_tools import selinux
from pytest_client_tools.selinux import SELinuxAVCChecker, add_known_avcs_to_skiplist

_SEPARATOR = "=" * 63
AUREPORT_OUTPUT = "\n".join(
    [
        "AVC Report",
        _SEPARATOR,
        "date time comm subj obj class action event",
        _SEPARATOR,
        "11/24/2026 10:00:00 insights-client "
        "system_u:system_r:insights_client_t:s0 system_u:object_r:var_log_t:s0 "
        "file write 100",
        "11/24/2026 10:00:01 rhsmcertd "
        "system_u:system_r:rhsmcertd_t:s0 system_u:object_r:etc_t:s0 "
        "file read 101",
    ]
)


class RecordingAVCChecker:
    def __init__(self):
        self.fields = []
        self.regexes = []

    def skip_avc_entry_by_fields(self, fields):
        self.fields.append(fields)

    def skip_avc_re(self, expression):
        self.regexes.append(expression)


def test_project_skiplist_is_injected():
    checker = RecordingAVCChecker()
    project_skips = [
        {"fields": {"subj": "system_u:system_r:rhsmcertd_t:s0"}},
        {"regex": r"known AVC pattern"},
    ]
    add_known_avcs_to_skiplist(checker, project_skips)

    assert len(checker.fields) == 1
    assert project_skips[0]["fields"] in checker.fields
    assert checker.regexes == [r"known AVC pattern"]


def test_empty_project_skiplist_does_not_apply_any_rules():
    checker = RecordingAVCChecker()
    add_known_avcs_to_skiplist(checker)

    assert checker.fields == []
    assert checker.regexes == []


@pytest.mark.parametrize(
    ("skip", "message"),
    [
        ([], "must be a mapping"),
        ({}, "exactly one of 'fields' or 'regex'"),
        ({"fields": None}, "fields' must be a mapping"),
        ({"fields": {}, "regex": "pattern"}, "exactly one of 'fields' or 'regex'"),
        ({"other": {}}, "exactly one of 'fields' or 'regex'"),
    ],
)
def test_invalid_project_skip_specification_fails(skip, message):
    with pytest.raises(ValueError, match=message):
        add_known_avcs_to_skiplist(RecordingAVCChecker(), [skip])


def test_selinux_disabled_disables_audit_collection(monkeypatch):
    from types import SimpleNamespace

    from pytest_client_tools import util

    monkeypatch.setattr(
        util.shutil,
        "which",
        lambda tool: "/usr/sbin/getenforce" if tool == "getenforce" else None,
    )
    monkeypatch.setattr(
        util,
        "logged_run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="Disabled\n", stderr=""
        ),
    )

    assert util.should_log_selinux_denials() is False


def _completed(stdout="", stderr="", returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_finish_flushes_then_closes_window_then_collects(monkeypatch):
    checker = SELinuxAVCChecker()
    checker.start_time = datetime(2026, 11, 24, 10, 0, 0)
    order = []

    def fake_flush():
        order.append("flush")
        # the window must not be closed yet when flushing
        assert checker.end_time is None

    monkeypatch.setattr(selinux, "flush_audit_events", fake_flush)

    def fake_get_avcs(skiplisted=True):
        order.append(("get_avcs", skiplisted))
        # the window must be closed by the time AVCs are collected
        assert checker.end_time is not None
        return iter([])

    monkeypatch.setattr(checker, "get_avcs", fake_get_avcs)

    checker.finish()

    assert order == ["flush", ("get_avcs", False)]
    assert checker.end_time is not None


def test_finish_collects_all_avcs_including_skiplisted(monkeypatch):
    checker = SELinuxAVCChecker()
    checker.start_time = datetime(2026, 11, 24, 10, 0, 0)
    monkeypatch.setattr(selinux, "flush_audit_events", lambda: None)
    monkeypatch.setattr(
        selinux,
        "_run_audit_tool",
        lambda cmd, **kwargs: _completed(stdout=AUREPORT_OUTPUT),
    )
    # a skiplisted AVC must still be collected by finish()
    checker.skip_avc_entry_by_fields({"comm": "rhsmcertd"})

    avcs = checker.finish()

    assert [avc["comm"] for avc in avcs] == ["insights-client", "rhsmcertd"]
    assert checker.last_report == AUREPORT_OUTPUT


def test_flush_audit_events_warns_when_marker_never_appears(monkeypatch, caplog):
    clock = iter(range(1000))  # monotonic() returns 0, 1, 2, ...
    monkeypatch.setattr(selinux.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(selinux.time, "sleep", lambda seconds: None)
    commands = []

    def fake_run_audit_tool(cmd, **kwargs):
        commands.append(cmd)
        return _completed(stdout="")  # the marker is never found

    monkeypatch.setattr(selinux, "_run_audit_tool", fake_run_audit_tool)

    with caplog.at_level(logging.WARNING, logger="pytest_client_tools"):
        selinux.flush_audit_events()

    assert any("timed out" in record.message for record in caplog.records)
    # the audit log was polled repeatedly while waiting for the marker
    assert sum(1 for cmd in commands if cmd[0] == "ausearch") > 1
