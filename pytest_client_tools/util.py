# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import dataclasses
import functools
import logging
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import time

from .logger import LOGGER

# rpm packages whose installed versions are part of the environment
# metadata: the components under test, and the SELinux policy that
# governs the AVC checks
_RPM_PACKAGES = ("insights-client", "insights-core", "selinux-policy")


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
        """Copy a file in the artifacts directory.

        The first capture of a file wins: a file collected under the same
        name is never overwritten, so snapshots taken earlier (e.g. at test
        end, before fixture teardowns rewrite the source files) are
        preserved.
        """
        self._path.mkdir(parents=True, exist_ok=True)
        dst = self._path / pathlib.Path(src).name
        if not dst.exists():
            shutil.copy2(src, self._path)

    def write_text(self, fn, data):
        self._path.mkdir(parents=True, exist_ok=True)
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
        self.failed = False

    def archive_test_log(self):
        self.handler.close()
        if self.logfile.exists():
            self.artifacts.copy(self.logfile)


def _os_compose(path="/etc/os-release"):
    """Return the build identifiers of the OS."""
    try:
        with open(path) as f:
            fields = {}
            for line in f:
                key, sep, value = line.partition("=")
                if sep:
                    fields[key.strip()] = value.strip().strip('"')
    except OSError:
        return "unknown"
    for key in ("BUILD_ID", "VERSION_ID"):
        if fields.get(key):
            return fields[key]
    return "unknown"


def _rpm_versions():
    """Return the installed versions of the relevant rpm packages."""
    versions = {}
    for package in _RPM_PACKAGES:
        try:
            proc = logged_run(
                ["rpm", "-q", package],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError:
            # rpm is not available (e.g. non-rpm systems)
            versions[package] = "unknown"
            continue
        versions[package] = (
            proc.stdout.strip() if proc.returncode == 0 else "not installed"
        )
    return versions


def _fips_enabled():
    """Return the FIPS mode of the system ("enabled"/"disabled") or
    "unknown"."""
    try:
        with open("/proc/sys/crypto/fips_enabled") as f:
            value = f.read().strip()
    except OSError:
        return "unknown"
    return {"1": "enabled", "0": "disabled"}.get(value, "unknown")


def _git(command):
    """Run a git command in the test sources, if they are a git checkout.

    The command runs in ``$TMT_TREE`` when set (tmt/Testing Farm check
    the sources out there, which may not be the current directory), and
    in the current directory otherwise.

    :return: The stripped stdout of the command, or ``None`` when git is
        unavailable or the sources are not a git checkout
    """
    cwd = os.environ.get("TMT_TREE") or None
    try:
        proc = logged_run(
            command,
            check=False,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _test_branch():
    """Return the git branch of the running test project.

    CI environments expose the branch under test in environment
    variables (``GIT_BRANCH``, ``BRANCH``, ``CHANGE_BRANCH``,
    ``GITHUB_HEAD_REF``), which also cover checkouts without ``.git``;
    they are preferred over querying the checkout, where a detached
    ``HEAD`` (typical in CI) is not a branch name at all.
    """
    for env_var in ("GIT_BRANCH", "BRANCH", "CHANGE_BRANCH", "GITHUB_HEAD_REF"):
        branch = os.environ.get(env_var)
        if branch:
            return branch
    branch = _git(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    if branch and branch != "HEAD":
        return branch
    return "unknown"


def _test_commit():
    """Return the short commit hash of the running test project.

    This is what actually makes a run reproducible: the branch can move
    (or be unknown for a detached checkout), the commit cannot.
    """
    return _git(["git", "rev-parse", "--short", "HEAD"]) or "unknown"


def collect_environment_metadata():
    """
    Collect metadata about the environment the tests run in.

    :return: The environment metadata as ``key: value`` lines
    :rtype: str
    """
    lines = [
        f"compose: {_os_compose()}",
        f"arch: {platform.machine()}",
        f"fips: {_fips_enabled()}",
        f"ENV_FOR_DYNACONF: {os.environ.get('ENV_FOR_DYNACONF', '')}",
        f"test branch: {_test_branch()}",
        f"test commit: {_test_commit()}",
    ]
    lines.extend(f"{name}: {version}" for name, version in _rpm_versions().items())
    return "\n".join(lines) + "\n"


def logged_run(*args, **kwargs):
    logged_args = kwargs.pop("logged_args", None)
    # never log the environment: it may carry credentials (e.g. Vault
    # tokens), and the debug log is archived with the test artifacts.
    # Log only option names to avoid leaking sensitive values passed in kwargs.
    logged_option_names = tuple(sorted(k for k in kwargs if k != "env"))
    LOGGER.debug(
        "running %s with options %s",
        logged_args if logged_args else args,
        logged_option_names,
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
    getenforce = shutil.which("getenforce")
    if getenforce:
        proc_getenforce = logged_run(
            [getenforce],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        selinux_mode = proc_getenforce.stdout.strip()
        if proc_getenforce.returncode != 0 or selinux_mode == "Disabled":
            LOGGER.info(
                "disabling SELinux denials collection because SELinux is disabled "
                f"(getenforce output: {selinux_mode or proc_getenforce.stderr.strip()})"
            )
            return False
    for tool in ["ausearch", "aureport", "auditctl"]:
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


def loop_until(predicate, poll_sec=5, timeout_sec=120, ignore_exceptions=()):
    """
    An helper function to handle a time periond waiting for an external service
    to update its state.

    an example:

       assert loop_until(lambda: insights_client.is_registered)

    The loop function checks predicate immediately, then retries every poll_sec
    seconds until the total time exceeds timeout_sec.
    """
    start = time.time()
    ok = False
    exception = None
    while (not ok) and (time.time() - start < timeout_sec):
        exception = None
        try:
            ok = predicate()
        except ignore_exceptions as exc:
            exception = exc
            ok = False
        if not ok:
            time.sleep(poll_sec)
    if exception is not None:
        raise exception
    return ok
