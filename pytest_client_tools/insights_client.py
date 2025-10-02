# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import configparser
import contextlib
import pathlib
import re
import subprocess
import uuid

from . import SystemNotRegisteredError
from .util import SavedFile, Version, logged_run


INSIGHTS_CLIENT_FILES_TO_SAVE = (
    SavedFile(pathlib.Path("/etc/insights-client/insights-client.conf")),
    SavedFile(
        pathlib.Path("/var/log/insights-client/insights-client.log"),
        remove_at_start=True,
    ),
    SavedFile(
        pathlib.Path("/var/log/insights-client/insights-client.log.1"),
        remove_at_start=True,
    ),
    SavedFile(
        pathlib.Path("/var/log/insights-client/insights-client.log.2"),
        remove_at_start=True,
    ),
    SavedFile(
        pathlib.Path("/var/log/insights-client/insights-client.log.3"),
        remove_at_start=True,
    ),
    SavedFile(
        pathlib.Path("/var/log/insights-client/insights-client-payload.log"),
        remove_at_start=True,
    ),
    SavedFile(
        pathlib.Path("/var/log/insights-client/insights-client-payload.log.1"),
        remove_at_start=True,
    ),
    SavedFile(
        pathlib.Path("/var/log/insights-client/insights-client-payload.log.2"),
        remove_at_start=True,
    ),
    SavedFile(
        pathlib.Path("/var/log/insights-client/insights-client-payload.log.3"),
        remove_at_start=True,
    ),
)


class InsightsClientConfig:
    """
    Insights Client configuration.

    This class represents the configuration of `insights-client`, i.e.
    `/etc/insights-client/insights-client.conf` by default.

    This class uses attributes to represents the various configuration bits:

    - setting an attribute for a known configuration key sets the corresponding
      configuration value
    - setting an attribute for an unknown configuration key only sets a new
      instance variable, without changing the actual configuration
    - getting an attribute for a known configuration key sets returns the
      configuration value if set, otherwise `KeyError` is raisen

    Please note that changing attributes does not automatically update the
    configuration file; `save()` must be called explicitly when needed.
    """

    # boolean config keys
    _KEYS_BOOL = {
        "analyze_container",
        "analyze_image_idanalyze_file",
        "analyze_mountpoint",
        "auto_config",
        "auto_update",
        "build_packagecache",
        "check_results",
        "checkin",
        "compliance",
        "core_collect",
        "debug",
        "disable_schedule",
        "enable_schedule",
        "force",
        "gpg",
        "keep_archive",
        "legacy_upload",
        "list_specs",
        "net_debug",
        "no_gpg",
        "no_upload",
        "obfuscate",
        "obfuscate_hostname",
        "offline",
        "quiet",
        "register",
        "reregister",
        "show_results",
        "silent",
        "status",
        "support",
        "test_connection",
        "to_json",
        "unregister",
    }
    # int config keys
    _KEYS_INT = {
        "retries",
        "cmd_timeout",
    }
    # float config keys
    _KEYS_FLOAT = {
        "http_timeout",
    }
    # string config keys
    _KEYS_STRING = {
        "ansible_host",
        "authmethod",
        "base_url",
        "branch_info",
        "branch_info_url",
        "compressor",
        "content_redaction_file",
        "display_name",
        "egg_gpg_path",
        "egg_path",
        "group",
        "logging_file",
        "loglevel",
        "obfuscation_list",
        "password",
        "proxy",
        "redaction_file",
        "remove_file",
        "tags_file",
        "upload_url",
        "username",
    }
    # bool & string config keys
    _KEYS_BOOL_STRING = {
        "cert_verify",
    }

    def __init__(self, path="/etc/insights-client/insights-client.conf"):
        self._path = path
        self.reload()

    def reload(self):
        """
        Reload the configuration.

        Reload the configuration from the underlying file, discarding all the
        values set in the instance.
        """
        with open(self._path) as f:
            self._config = configparser.RawConfigParser()
            self._config.read_file(f, source=self._path)
            with contextlib.suppress(configparser.DuplicateSectionError):
                self._config.add_section("insights-client")

    def save(self):
        """
        Save the configuration.

        Save the configuration values to the underlying configuration file.
        """
        with open(self._path, "w") as f:
            self._config.write(f, space_around_delimiters=False)

    def __getattr__(self, name):
        if name in self._KEYS_BOOL | self._KEYS_BOOL_STRING:
            read_func = self._config.getboolean
        elif name in self._KEYS_INT:
            read_func = self._config.getint
        elif name in self._KEYS_FLOAT:
            read_func = self._config.getfloat
        elif name in self._KEYS_STRING:
            read_func = self._config.get
        else:
            raise KeyError(name)
        try:
            try:
                return read_func("insights-client", name)
            except ValueError:
                return self._config.get("insights-client", name)
        except configparser.NoOptionError:
            raise KeyError(name)

    def __setattr__(self, name, value):
        if name in (
            self._KEYS_BOOL
            | self._KEYS_INT
            | self._KEYS_FLOAT
            | self._KEYS_STRING
            | self._KEYS_BOOL_STRING
        ):
            self._config.set("insights-client", name, str(value))
            return
        super().__setattr__(name, value)


class InsightsClient:
    """
    Insights Client.

    This class represents the `insights-client` tool.

    It exposes a public `config` attribute (which is `InsightsClientConfig`)
    representing the configuration of `insights-client`, i.e.
    `/etc/insights-client/insights-client.conf`.
    """

    def __init__(self):
        self.config = InsightsClientConfig()

    @property
    def is_registered(self):
        """
        Query whether `insights-client` is registered.

        :return: Whether `insights-client` is registered
        :rtype: bool
        """
        proc = self.run("--status", check=False, selinux_context=None)
        if proc.returncode in [0, 1] and any(
            i in proc.stdout for i in ["NOT", "unregistered", "401: Unauthorized"]
        ):
            return False
        if proc.returncode == 0 and any(
            i in proc.stdout for i in ["This host is registered", "Registered"]
        ):
            return True
        proc.check_returncode()

    @property
    def core_version(self):
        """
        Return the version of insights-core as
        [`Version`][pytest_client_tools.util.Version] object.

        :return: The version of the insights-core in use.
        :rtype: pytest_client_tools.util.Version
        """
        proc = self.run("--version", selinux_context=None)
        m = re.search(r"^Core: (.+)-(\d+|dev)$", proc.stdout, re.MULTILINE)
        assert m
        return Version(m.group(1))

    @property
    def version(self):
        """
        Return the version of insights-client as
        [`Version`][pytest_client_tools.util.Version] object.

        :return: The version of the insights-client in use.
        :rtype: pytest_client_tools.util.Version
        """
        proc = self.run("--version", selinux_context=None)
        m = re.search(r"^Client: (.+)$", proc.stdout, re.MULTILINE)
        assert m
        return Version(m.group(1))

    @property
    def uuid(self):
        """
        Return the UUID of the registered system.

        Raises `SystemNotRegisteredError` if the system is not registered.

        :return: The UUID of the system
        :rtype: uuid.UUID
        """
        if not self.is_registered:
            raise SystemNotRegisteredError()
        with open("/etc/insights-client/machine-id", "r") as f:
            return uuid.UUID(f.read().strip())

    def run(
        self,
        *args,
        check=True,
        text=True,
        selinux_context="system_u:system_r:insights_client_t:s0",
    ):
        """
        Run `insights-client` with the specified arguments.

        This function is a simple wrapper around invoking `insights-client`
        with a specified list of arguments, returning the result of the
        execution directly from `subprocess`.

        :param args: The actual arguments to run using `insights-client`
        :type args: list
        :param check: Whether raise an exception if the process exits with
            a return code different than 0
        :type check: bool
        :param text: Whether the stdin/stdout of the process are textual
            (and not bytes)
        :type text: bool
        :param selinux_context: SELinux context in which to run insights-client
        :type selinux_context: str or None
        :return: The result of the command execution
        :rtype: subprocess.CompletedProcess
        """
        if selinux_context is not None:
            cmd = ["runcon", selinux_context, "insights-client"] + list(args)
        else:
            cmd = ["insights-client"] + list(args)

        return logged_run(
            cmd,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
        )

    def register(self, selinux_context=None):
        """
        Register with `insights-client`.

        Invokes `insights-client --register`.

        :param selinux_context: SELinux context in which to run insights-client,
            for more details see `InsightsClient.run`
        :type selinux_context: str or None
        :return: The result of the command execution
        :rtype: subprocess.CompletedProcess
        """
        return self.run("--register", selinux_context=selinux_context)

    def unregister(self, selinux_context=None):
        """
        Unregister with `insights-client`.

        Invokes `insights-client --unregister`.

        :param selinux_context: SELinux context in which to run insights-client,
            for more details see `InsightsClient.run`
        :type selinux_context: str or None
        :return: The result of the command execution
        :rtype: subprocess.CompletedProcess
        """
        return self.run("--unregister", selinux_context=selinux_context)
