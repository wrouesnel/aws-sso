"""Requests helper functions"""
from typing import Optional

from furl import furl

import requests


class BaseUrlSession(requests.Session):
    """Requests session which combines all URLs using fURL which gives better behavior"""
    base_url = None

    def __init__(self, base_url:Optional[str]=None):
        self.base_url = furl("") if base_url is None else furl(base_url)
        super(BaseUrlSession, self).__init__()

    def request(self, method, url,
            params=None, data=None, headers=None, cookies=None, files=None,
            auth=None, timeout=None, allow_redirects=True, proxies=None,
            hooks=None, stream=None, verify=None, cert=None, json=None):
        """Send the request after generating the complete URL."""

        return super(BaseUrlSession, self).request(
            method=method,
            url=self.base_url / url,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            hooks=hooks,
            stream=stream,
            verify=verify,
            cert=cert,
            json=json,
        )
