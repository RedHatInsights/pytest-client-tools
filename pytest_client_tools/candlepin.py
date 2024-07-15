# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import time

from .restclient import RestClient
from .util import Version


class Candlepin:
    """
    Candlepin

    This class represents a Candlepin server.
    """

    def __init__(self, host, port, prefix, insecure, verify=False):
        self._host = host
        self._port = port
        self._prefix = prefix
        self._insecure = insecure
        self._rest_client = RestClient(
            base_url=f"https://{self._host}:{self._port}{self._prefix}",
            verify=verify,
        )

    @property
    def host(self):
        """
        The hostname of the Candlepin server.
        """
        return self._host

    @property
    def port(self):
        """
        The port of the Candlepin server.
        """
        return self._port

    @property
    def prefix(self):
        """
        The prefix of the Candlepin server.
        """
        return self._prefix

    @property
    def insecure(self):
        """
        Whether verify the SSL connection to the Candlepin server.
        """
        return self._insecure

    def get(self, path, **kwargs):
        """
        Perform a GET REST call.
        """
        return self._rest_client.get(path, **kwargs)

    def post(self, path, data, **kwargs):
        """
        Perform a POST REST call.
        """
        return self._rest_client.post(path, data, **kwargs)

    def status(self):
        """
        Get the status of the Candlepin server.

        This is a shortcut for querying the `/status` endpoint, returning its
        output as JSON.

        :returns: The JSON dictionary of Candlepin's `/status` endpoint
        :rtype: dict
        """
        return self.get("status").json()

    def version(self):
        """
        Get the version string of the Candlepin server as
        [`Version`][pytest_client_tools.util.Version] object.

        :return: The version of Candlepin
        :rtype: pytest_client_tools.util.Version
        """
        return Version(self.status()["version"])


def ping_candlepin(candlepin, initial_wait=None):
    if initial_wait:
        time.sleep(initial_wait)
    for i in range(1, 60):
        try:
            candlepin.status()
            return
        except Exception as e:
            if i >= 59:
                raise e from None
            time.sleep(1)
