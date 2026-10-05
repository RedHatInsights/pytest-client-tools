# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import os
import re
import subprocess
from datetime import datetime

_AUDIT_DATE_FORMAT = "%m/%d/%y"
_AUDIT_ENV = {**os.environ, "LC_ALL": "C", "LC_TIME": "C"}


def _parse_execve_event_block(event_lines):
    """
    Parse a block of audit lines (one event) to extract process info.
    Correlates SYSCALL (context) with EXECVE (full arguments).
    """
    # Join lines to make searching easier, or iterate
    full_text = "\n".join(event_lines)

    # 1. Extract contexts from SYSCALL
    # scontext = subject context (parent process that executed)
    scontext_match = re.search(r"(?:subj|scontext)=([^\s]+)", full_text)
    if not scontext_match:
        return None
    scontext = scontext_match.group(1)

    # tcontext = target context (file being executed)
    # newcontext = actual running context if setexeccon was used
    newcontext_match = re.search(r"newcontext=([^\s]+)", full_text)
    tcontext_match = re.search(r"tcontext=([^\s]+)", full_text)

    # Running context is newcontext if setexeccon was used, otherwise tcontext
    if newcontext_match:
        running_context = newcontext_match.group(1)
    elif tcontext_match:
        running_context = tcontext_match.group(1)
    else:
        # Fallback to scontext if neither found (shouldn't happen normally)
        running_context = scontext

    # 2. Extract Command/Arguments from EXECVE
    if "type=EXECVE" not in full_text:
        return None

    # Extract all arguments to reconstruct the command roughly
    args = re.findall(r'a\d+=(?:"([^"]+)"|([^\s]+))', full_text)
    cmd_args = [x[0] or x[1] for x in args]
    cmd_string = " ".join(cmd_args)

    # 3. Filter: Is this the process we care about?
    # We only care if the arguments mention insights-client structure
    target_markers = ["insights-client", "insights_client", "insights-core", "run.py"]
    if not any(marker in cmd_string for marker in target_markers):
        return None
    # Comm is usually the base command (first arg or explicit comm field)
    comm_match = re.search(r'comm="([^"]+)"', full_text)
    comm = (
        comm_match.group(1) if comm_match else (cmd_args[0] if cmd_args else "unknown")
    )
    # Return format: (comm_name, source_context, running_context)
    return (comm, scontext, running_context)


def _check_process_contexts_from_audit(start_time, end_time=None):
    """Check SELinux contexts of executed processes from audit logs.
    Groups lines by event ID to correlate EXECVE arguments with SYSCALL context.
    """
    contexts = []

    # Prepare ausearch command
    # Note: We search for both SYSCALL and EXECVE to ensure we get the full block
    cmd = [
        "ausearch",
        "--message",
        "SYSCALL,EXECVE",
        "--start",
        start_time.strftime(_AUDIT_DATE_FORMAT),
        start_time.strftime("%H:%M:%S"),
    ]
    if end_time:
        cmd.extend(
            [
                "--end",
                end_time.strftime(_AUDIT_DATE_FORMAT),
                end_time.strftime("%H:%M:%S"),
            ]
        )

    # Helper to process a block of lines
    def process_block(lines):
        if not lines:
            return
        parsed = _parse_execve_event_block(lines)
        if parsed:
            contexts.append(parsed)

    # ausearch and aureport parse dates using the locale's short-date format.
    # Use C's stable MM/DD/YY format; some audit releases reject four-digit years.
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=5, check=False, env=_AUDIT_ENV
    )
    if result.returncode == 0 and result.stdout:
        current_event = []
        for line in result.stdout.splitlines():
            if line.strip() == "----":
                process_block(current_event)
                current_event = []
            else:
                current_event.append(line)
        process_block(current_event)  # Process the last block
    return contexts


# Classes
class AuditLogEntry:
    def __init__(self, keys, values):
        self.fields = dict(zip(keys, values))
        self._text = None

    def __getitem__(self, item):
        return self.fields[item]

    def __str__(self):
        if self._text is None:
            self._text = subprocess.run(
                ["ausearch", "-i", "-a", f"{self.serial}"],
                stdout=subprocess.PIPE,
                check=True,
            ).stdout.decode()
        return self._text

    @property
    def serial(self):
        return self["event"]


class SELinuxAVCChecker:
    """Context manager for checking SELinux avc during a time period.
    This context manager automatically tracks start_time and end_time,
    removing the need for manual time tracking in tests.
    """

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.avc_skiplist = []
        self.last_report = ""

    def __enter__(self):
        self.start_time = datetime.now()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = datetime.now()
        return False

    def skip_avc_re(self, expression):
        expression = re.compile(expression)
        condition = lambda entry: re.search(expression, str(entry))  # noqa: E731
        self.avc_skiplist.append(condition)
        return condition

    def skip_avc_entry_by_fields(self, fields):
        condition = lambda entry: all(  # noqa: E731
            entry[key] == value for key, value in fields.items()
        )
        self.avc_skiplist.append(condition)
        return condition

    def skip_all_avcs(self):
        condition = lambda entry: True  # noqa: E731
        self.avc_skiplist.append(condition)
        return condition

    def is_skiplisted(self, entry):
        return any(condition(entry) for condition in self.avc_skiplist)

    # aureport's exact separator row, used both to find the header and to
    # skip repeated separators in the data section below.
    _SEPARATOR = "=" * 63

    def get_avcs(self, skiplisted=True):
        result = subprocess.run(
            self.aureport_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_AUDIT_ENV,
        )
        # aureport (like ausearch, which it shares exit-status semantics with)
        # exits 1 both when nothing was found and on minor argument/file
        # errors, so a non-zero exit alone isn't a reliable failure signal.
        # A clean "nothing found" run leaves stderr empty, so only treat this
        # as a hard failure when aureport actually wrote something to stderr.
        stderr = result.stderr.decode(errors="replace").strip()
        if result.returncode != 0 and stderr:
            raise RuntimeError(f"aureport failed (exit {result.returncode}): {stderr}")

        output = result.stdout.decode()
        self.last_report = output
        lines = [line for line in output.splitlines() if line.strip()]

        if not lines or "<no events of interest were found>" in output:
            return

        # Find the column-header line: it sits between two separator rows.
        keys = None
        data_start = None
        for i, line in enumerate(lines):
            if (
                line == self._SEPARATOR
                and i + 2 < len(lines)
                and lines[i + 2] == self._SEPARATOR
            ):
                keys = lines[i + 1].split()
                data_start = i + 3
                break

        if keys is None or data_start is None:
            raise RuntimeError(f"unrecognized aureport output format:\n{output}")

        for line in lines[data_start:]:
            if line == self._SEPARATOR:
                continue
            entry = AuditLogEntry(keys, line.split())
            if skiplisted and self.is_skiplisted(entry):
                continue
            yield entry

    @property
    def start_aureport_time(self):
        return self.start_time.strftime(_AUDIT_DATE_FORMAT), self.start_time.strftime(
            "%H:%M:%S"
        )

    @property
    def end_aureport_time(self):
        return self.end_time.strftime(_AUDIT_DATE_FORMAT), self.end_time.strftime(
            "%H:%M:%S"
        )

    @property
    def aureport_command(self):
        cmd = [
            "aureport",
            "--avc",
            "--interpret",
            "--start",
            *self.start_aureport_time,
        ]
        if self.end_time:
            cmd += ["--end", *self.end_aureport_time]
        return cmd

    def get_process_contexts(self):
        # Get process contexts from execve events during the context manager period.
        return _check_process_contexts_from_audit(self.start_time, self.end_time)


def add_known_avcs_to_skiplist(avc_checker, project_skips=()):
    """Add project-provided AVC skip specifications to the checker.

    Each project specification must contain exactly one of ``fields`` or
    ``regex``. Project fixtures should return only rules applicable to the
    current test.
    """
    for skip in project_skips:
        if not isinstance(skip, dict):
            raise ValueError("AVC skip specification must be a mapping")
        has_fields = "fields" in skip
        has_regex = "regex" in skip
        if has_fields == has_regex:
            raise ValueError(
                "AVC skip specification must contain exactly one of 'fields' or 'regex'"
            )
        if has_fields:
            if not isinstance(skip["fields"], dict):
                raise ValueError("AVC skip 'fields' must be a mapping")
            avc_checker.skip_avc_entry_by_fields(skip["fields"])
        else:
            avc_checker.skip_avc_re(skip["regex"])
