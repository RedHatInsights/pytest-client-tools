# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import json
import pathlib
import re
import subprocess

from .util import SavedFile, logged_run, Version, redact_arguments


RHC_FILES_TO_SAVE = (
    SavedFile(pathlib.Path("/etc/rhc/config.toml")),
    SavedFile(pathlib.Path("/etc/rhc/workers/rhc-package-manager.toml")),
    SavedFile(pathlib.Path("/etc/yggdrasil/config.toml")),
)


class Rhc:
    """
    Rhc.

    This class represents the `rhc` tool.
    """

    def __init__(self):
        pass

    @property
    def is_registered(self):
        """
        Query whether `rhc` is registered.

        :return: Whether `rhc` is registered
        :rtype: bool
        """
        proc = self.run("status", "--format", "json", check=False)
        if proc.returncode in [0, 1]:
            doc = json.loads(proc.stdout)
            return doc["rhsm_connected"]
        proc.check_returncode()

    @property
    def version(self):
        """
        Return the version of rhc as
        [`Version`][pytest_client_tools.util.Version] object.

        :return: The version of the rhc in use.
        :rtype: pytest_client_tools.util.Version
        """
        proc = self.run("--version")
        m = re.search(r"^rhc version (.+)$", proc.stdout, re.MULTILINE)
        assert m
        return Version(m.group(1))

    def run(self, *args, check=True, text=True):
        """
        Run `rhc` with the specified arguments.

        This function is a simple wrapper around invoking `rhc` with a
        specified list of arguments, returning the result of the execution
        directly from `rhc`.

        :param args: The actual arguments to run using `rhc`
        :type args: list
        :param check: Whether raise an exception if the process exits with
            a return code different than 0
        :type check: bool
        :param text: Whether the stdin/stdout of the process are textual
            (and not bytes)
        :type text: bool
        :return: The result of the command execution
        :rtype: subprocess.CompletedProcess
        """
        logged_args = redact_arguments(
            list(args),
            [
                "--activation-key",
                "--organization",
                "--password",
                "--username",
            ],
        )
        return logged_run(
            ["rhc"] + list(args),
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
            logged_args=logged_args,
        )

    def connect(
        self, username=None, password=None, org=None, activationkey=None, *extra_args
    ):
        """
        Connect with `rhc`.

        Invokes `rhc connect`.

        :param username: The username to use for registering
        :type username: str, optional
        :param password: The password to use for registering
        :type password: str, optional
        :param org: The organization to use for registering
        :type org: str, optional
        :param activationkey: The activation keys to use for registering;
            this is single string with keys separated by comma
        :type activationkey: str, optional
        :param extra_args: Additional parameters to run, passed straight to
            `rhc connect`
        :type extra_args: list, optional
        :return: The result of the command execution
        :rtype: subprocess.CompletedProcess
        """
        args = []
        if username:
            args.append("--username")
            args.append(username)
        if password:
            args.append("--password")
            args.append(password)
        if org:
            args.append("--organization")
            args.append(org)
        if activationkey:
            args.append("--activation-key")
            args.append(activationkey)

        proc = self.run("connect", *args, *extra_args, check=False)
        if proc.returncode not in [0, 1]:
            proc.check_returncode()
        return proc

    def disconnect(self):
        """
        Disconnect with `rhc`.

        Invokes `rhc disconnect`.

        :return: The result of the command execution
        :rtype: subprocess.CompletedProcess
        """
        return self.run("disconnect")
