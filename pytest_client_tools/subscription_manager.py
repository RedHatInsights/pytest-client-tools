# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import pathlib
import re
import subprocess
import uuid

from . import SystemNotRegisteredError
from .util import SavedFile, logged_run, redact_arguments

SUBMAN_FILES_TO_SAVE = (
    SavedFile(pathlib.Path("/etc/rhsm/rhsm.conf")),
    SavedFile(pathlib.Path("/var/log/rhsm/rhsm.log"), remove_at_start=True),
    SavedFile(pathlib.Path("/var/log/rhsm/rhsmcertd.log"), remove_at_start=True),
)


class SubscriptionManager:
    """
    Subscription Manager.

    This class represents the `subscription-manager` tool.
    """

    def __init__(self):
        pass

    @property
    def is_registered(self):
        """
        Query whether `subscription-manager` is registered.

        :return: Whether `subscription-manager` is registered
        :rtype: bool
        """
        proc = self.run("identity", check=False)
        if proc.returncode == 0:
            return True
        if proc.returncode == 1:
            return False
        proc.check_returncode()

    @property
    def uuid(self):
        """
        Return the UUID of the registered system.

        Raises `SystemNotRegisteredError` if the system is not registered.

        :return: The UUID of the system
        :rtype: uuid.UUID
        """
        proc = self.run("identity", check=False)
        if proc.returncode == 0:
            m = re.search(
                r"^system identity: ([-0-9A-Fa-f]{36})$",
                proc.stdout,
                flags=re.MULTILINE,
            )
            return uuid.UUID(m.group(1))
        if proc.returncode == 1:
            raise SystemNotRegisteredError()
        proc.check_returncode()

    def run(self, *args, check=True, text=True):
        """
        Run `subscription-manager` with the specified arguments.

        This function is a simple wrapper around invoking
        `subscription-manager` with a specified list of arguments, returning
        the result of the execution directly from `subprocess`.

        :param args: The actual arguments to run using `subscription-manager`
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
                "--activationkey",
                "--org",
                "--password",
                "--server.proxy_password",
                "--server.proxy_user",
                "--username",
            ],
        )
        return logged_run(
            ["subscription-manager"] + list(args),
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
            logged_args=logged_args,
        )

    def config(self, **kwargs):
        args = []
        sections = ("server_", "rhsm_", "rhsmcertd_", "logging_")
        for k, v in kwargs.items():
            if k.startswith(sections) and v is not None:
                args.append(f"--{k.replace('_', '.', 1)}={v}")
        if not args:
            return

        self.run("config", *args)

    def register(
        self,
        username=None,
        password=None,
        org=None,
        activationkey=None,
        environments=None,
        *extra_args,
    ):
        """
        Register with `subscription-manager`.

        Invokes `subscription-manager register`.

        :param username: The username to use for registering
        :type username: str, optional
        :param password: The password to use for registering
        :type password: str, optional
        :param org: The organization to use for registering
        :type org: str, optional
        :param activationkey: The activation keys to use for registering;
            this can be either a list of keys, or a single string with keys
            separated by comma
        :type activationkey: str or list, optional
        :param environments: The environments to use for registering;
            this can be either a list of environments, or a single string with
            environments separated by comma
        :type environments: str or list, optional
        :param extra_args: Additional parameters to run, passed straight to
            `subscription-manager register`
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
            args.append("--org")
            args.append(org)
        if activationkey:
            args.append("--activationkey")
            if isinstance(activationkey, list):
                args.append(",".join(activationkey))
            else:
                args.append(activationkey)
        if environments:
            args.append("--environment")
            if isinstance(environments, list):
                args.append(",".join(environments))
            else:
                args.append(environments)

        return self.run("register", *args, *extra_args)

    def unregister(self):
        """
        Unregister with `subscription-manager`.

        Invokes `subscription-manager unregister`.

        :return: The result of the command execution
        :rtype: subprocess.CompletedProcess
        """
        return self.run("unregister")


def stop_rhsmcertd():
    logged_run(
        ["systemctl", "stop", "rhsmcertd.service"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    pkill_proc = logged_run(
        ["pkill", "-e", "-x", "rhsmcertd"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if pkill_proc.returncode not in [0, 1]:
        pkill_proc.check_returncode()
