# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import requests
from time import sleep

from .logger import LOGGER
from .restclient import RestClient


class Inventory:
    """
    Inventory

    This class represents an Inventory server.
    """

    def __init__(self, base_url, verify=True):
        self._rest_client = RestClient(
            base_url=base_url,
            verify=verify,
            cert=(
                "/etc/pki/consumer/cert.pem",
                "/etc/pki/consumer/key.pem",
            ),
        )
        self._insights_client = None

    @property
    def base_url(self):
        """
        The base URL of the Inventory server.
        """
        return self._rest_client.base_url

    def get(self, path, **kwargs):
        """
        Perform a GET REST call.
        """
        return self._rest_client.get(path, **kwargs)

    def delete(self, path, **kwargs):
        """
        Perform a DELETE REST call.
        """
        return self._rest_client.delete(path, **kwargs)

    def this_system(self, retries=3, delay=5):
        """
        Query Inventory for the current system.

        This assumes the current system is already registered with
        `insights-client`. Raises `SystemNotRegisteredError` if the system
        is not registered.

        :param retries: Number of times to retry the request
        :param delay: Seconds to wait after GET request
        :return: The dict of the current system in Inventory
        :rtype: dict
        """
        if not self._insights_client:
            raise RuntimeError(
                "Inventory.this_system(): cannot invoke without insights_client"
            )
        path = f"hosts?insights_id={self._insights_client.uuid}"

        for attempt in range(retries):
            try:
                res_json = self.get(path).json()
                sleep(delay)
                if res_json["total"] == 1:
                    return res_json["results"][0]
            except requests.exceptions.RequestException as e:
                LOGGER.warning(f"Attempt {attempt+1} failed with {e}")

        raise RuntimeError(
            f"Inventory.this_system(): {res_json['total']} hosts returned "
            f"for the current UUID ({self._insights_client.uuid})"
        )

    def this_system_profile(self):
        """
        Query Inventory for the system profile of the current system.

        This assumes the current system is already registered with
        `insights-client`.

        :return: The dict of the system profile of the current system in
                 Inventory
        :rtype: dict
        """
        if not self._insights_client:
            raise RuntimeError(
                "Inventory.this_system_profile(): cannot invoke without "
                "insights_client"
            )
        this = self.this_system()
        inventory_id = this["id"]
        path = f"hosts/{inventory_id}/system_profile"
        res_json = self.get(path).json()
        if res_json["total"] != 1:
            raise RuntimeError(
                f"Inventory.this_system_profile(): {res_json['total']} hosts "
                f"returned for the current UUID ({self._insights_client.uuid})"
            )
        return res_json["results"][0]["system_profile"]

    def this_system_tags(self):
        """
        Query Inventory for the tags of the current system.

        This assumes the current system is already registered with
        `insights-client`.

        :return: The dict of the tags of the current system in Inventory
        :rtype: dict
        """
        if not self._insights_client:
            raise RuntimeError(
                "Inventory.this_system_tags(): cannot invoke without insights_client"
            )
        this = self.this_system()
        inventory_id = this["id"]
        path = f"hosts/{inventory_id}/tags"
        res_json = self.get(path).json()
        if res_json["total"] != 1:
            raise RuntimeError(
                f"Inventory.this_system_tags(): {res_json['total']} hosts "
                f"returned for the current UUID ({self._insights_client.uuid})"
            )
        return res_json["results"][inventory_id]
