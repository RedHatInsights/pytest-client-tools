# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import dataclasses
import functools
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

from .logger import LOGGER


@dataclasses.dataclass
class SavedFile:
    path: pathlib.Path
    remove_at_start: bool = False


@functools.total_ordering
class Version:
    """
    Version.

    A simple representation of a version number/string in the format `X`,
    or `X.Y`, or `X.Y.Z`, or in general a sequence of dot-spearated numbers.
    Pre-release markers such as "alpha/beta/etc" are not supported.
    """

    def __init__(self, *args):
        """
        Create a new Version object.

        The passed arguments can either of:

        - a single string which is parsed
        - integer arguments representing the component of the version number

        Examples:
        ```python
        >>> Version("1.2")
        Version(1.2)
        >>> Version(1, 3)
        Version(1.3)
        >>> Version(1, 3) == Version("1.2")
        False
        >>> Version(1, 3, 1) >= Version("1.3")
        True
        ```
        """
        if len(args) == 1 and isinstance(args[0], str):
            parts = args[0].split(".")
            self._bits = [int(p) for p in parts]
        else:
            self._bits = [int(p) for p in args]

    def __lt__(self, other):
        if not isinstance(other, Version):
            return False
        return self._bits < other._bits

    def __eq__(self, other):
        if not isinstance(other, Version):
            return False
        return self._bits == other._bits

    def __str__(self):
        return ".".join([str(i) for i in self._bits])

    def __repr__(self):
        return f"Version({self.__str__()})"


class ClientToolsPluginData:
    def __init__(self):
        self.running_data = {}
        self.global_running_data = NodeRunningData()
        self.global_running_data.handler.setLevel(logging.DEBUG)
        LOGGER.addHandler(self.global_running_data.handler)
        self.log_selinux_audits = should_log_selinux_denials()


class ArtifactsCollector:
    def __init__(self, name=None, module=None, cls=None):
        self._path = self._init_path(name, module, cls)

    def _init_path(self, name, module, cls):
        p = pathlib.Path.cwd()
        p /= "artifacts"
        if module:
            p /= module.__name__
        if cls:
            p /= cls.__name__
        if name:
            p /= name
        return p

    def copy(self, src):
        self._path.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, self._path)

    def write_text(self, fn, data):
        (self._path / fn).write_text(data)


class NodeRunningData:
    def __init__(self, item=None):
        self._tempdir = tempfile.TemporaryDirectory()
        self.tmp_path = pathlib.Path(self._tempdir.name)
        self.artifacts = ArtifactsCollector(
            name=item.name if item else None,
            module=item.module if item else None,
            cls=item.cls if item else None,
        )
        self.logfile = self.tmp_path / "test.log"
        self.handler = logging.FileHandler(self.logfile, delay=True)
        self.handler.setFormatter(
            logging.Formatter(
                "%(asctime)s: %(name)s: %(funcName)s: %(levelname)s: %(message)s"
            )
        )
        self.timestamp = None

    def archive_test_log(self):
        self.handler.close()
        if self.logfile.exists():
            self.artifacts.copy(self.logfile)


def logged_run(*args, **kwargs):
    logged_args = kwargs.pop("logged_args", None)
    LOGGER.debug(
        "running %s with options %s", logged_args if logged_args else args, kwargs
    )
    check = kwargs.pop("check", False)
    # switch "text" (if present) into "universal_newlines" for Python < 3.7
    if sys.version_info[:2] < (3, 7):
        text = kwargs.pop("text", None)
        if text is not None:
            kwargs["universal_newlines"] = text
    try:
        proc = subprocess.run(*args, **kwargs)
        if logged_args:
            proc.args = logged_args
        LOGGER.debug("result: %s", proc)
        if check:
            proc.check_returncode()
    except subprocess.SubprocessError as e:
        if hasattr(e, "cmd") and logged_args:
            e.cmd = logged_args
        raise e from None
    return proc


def should_log_selinux_denials():
    def require_tool(tool):
        if not shutil.which(tool):
            LOGGER.info(
                f"disabling SELinux denials collection because '{tool}' is "
                "not available"
            )
            return False
        return True

    if os.environ.get("PYTEST_CLIENT_TOOLS_DISABLE_SELINUX", None):
        LOGGER.info(
            "disabling SELinux denials collection because the environment "
            " variable PYTEST_CLIENT_TOOLS_DISABLE_SELINUX is set"
        )
        return False
    for tool in ["ausearch", "auditctl"]:
        if not require_tool(tool):
            return False
    proc_systemctl = logged_run(
        [
            "systemctl",
            "show",
            "--property",
            "SubState",
            "--value",
            "auditd.service",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    auditd_status = proc_systemctl.stdout.strip()
    if auditd_status not in ["running"]:
        LOGGER.info(
            "disabling SELinux denials collection because auditd is not running "
            f"(status: {auditd_status})"
        )
        return False
    return True


def redact_arguments(args, redact_list):
    REDACTED_MARK = "<redacted>"
    new_args = []
    to_redact = False
    for arg in args:
        if to_redact:
            new_args.append(REDACTED_MARK)
            to_redact = False
            continue
        if arg in redact_list:
            new_args.append(arg)
            to_redact = True
            continue
        redact_item = next(
            (item for item in redact_list if arg.startswith(item + "=")),
            None,
        )
        if redact_item:
            new_args.append(f"{redact_item}={REDACTED_MARK}")
            continue
        new_args.append(arg)
    return new_args


def loop_until(predicate, poll_sec=5, timeout_sec=120):
    """
    An helper function to handle a time periond waiting for an external service
    to update its state.

    an example:

       assert loop_until(lambda: insights_client.is_registered)

    The loop function will retry to run predicate every 5secs
    until the total time exceeds timeout_sec.
    """
    start = time.time()
    ok = False
    while (not ok) and (time.time() - start < timeout_sec):
        time.sleep(poll_sec)
        ok = predicate()
    return ok
