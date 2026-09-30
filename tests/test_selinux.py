import pytest

from pytest_client_tools.selinux import add_known_avcs_to_skiplist


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
