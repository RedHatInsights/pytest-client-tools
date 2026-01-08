# SPDX-FileCopyrightText: Red Hat
# SPDX-License-Identifier: MIT

import requests
import urllib3

from .logger import LOGGER


class RestClient:
    """
    RestClient

    This class represents a client to perform REST calls.
    """

    def __init__(self, base_url, verify=True, cert=None, proxies=None):
        self._base_url = base_url
        self._verify = verify
        self._session = requests.Session()
        self._request_kwargs = {
            "headers": {
                "Content-type": "application/json",
            },
            "verify": self._verify,
        }
        if cert:
            self._request_kwargs["cert"] = cert

        if proxies:
            self._request_kwargs["proxies"] = proxies

    @property
    def base_url(self):
        """
        The base URL of the REST server.
        """
        return self._base_url

    def _request(self, req_type, path, **kwargs):
        actual_kwargs = self._request_kwargs
        actual_kwargs.update(kwargs)
        if not self._verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        LOGGER.debug(
            "requesting %s for %s with args=%s",
            req_type,
            f"{self._base_url}/{path}",
            actual_kwargs,
        )
        response = self._session.request(
            req_type, f"{self._base_url}/{path}", **actual_kwargs
        )
        LOGGER.debug("result: %s, %s", response, response.text)
        response.raise_for_status()
        return response

    def get(self, path, **kwargs):
        """
        Perform a GET REST call.
        """
        return self._request("GET", path, **kwargs)

    def delete(self, path, **kwargs):
        """
        Perform a DELETE REST call.
        """
        return self._request("DELETE", path, **kwargs)

    def post(self, path, data, **kwargs):
        """
        Perform a POST REST call.
        """
        return self._request("POST", path, json=data, **kwargs)
