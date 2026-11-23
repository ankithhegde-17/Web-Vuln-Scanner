"""Shared machinery for active checks: injection points and the injector.

An *injection point* is a single place where user input reaches the server:
one query-string parameter, or one form field. Active checks don't care
whether the point came from the crawler or from a --urls seed file; they just
receive a list of InjectionPoint objects and probe each one.

The *injector* (`send_with`) takes an injection point and a payload, puts the
payload into that one parameter (leaving the others at their baseline
values), and sends the request through the shared rate-limited client.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

import requests

from scanner.http_client import RateLimitedClient
from scanner.models import Finding

# A harmless value we drop into a field when a form has no default, just so
# the request looks realistic. Not a payload.
BENIGN_VALUE = "test"


@dataclass
class InjectionPoint:
    """One testable parameter.

    method   "GET" or "POST".
    url      Where to send the request. For GET this is the URL without its
             query string; the query is rebuilt from `params`. For POST it is
             the form's action URL.
    params   Every parameter at this point with its baseline value. We send
             all of them each time so the request is valid; we only change the
             one named by `param`.
    param    The name of the parameter this injection point targets.
    source   Human-readable origin, e.g. "query parameter 'q'" or
             "form field 'email' on http://host/login".
    """

    method: str
    url: str
    params: dict[str, str]
    param: str
    source: str = ""

    def with_payload(self, payload: str) -> dict[str, str]:
        """Return a copy of params with just `param` set to `payload`."""
        merged = dict(self.params)
        merged[self.param] = payload
        return merged


def send_with(client: RateLimitedClient, point: InjectionPoint, payload: str,
              allow_redirects: bool = False) -> requests.Response | None:
    """Send the injection point's request with `payload` in the target param."""
    values = point.with_payload(payload)
    if point.method == "GET":
        # Strip any existing query; `params` becomes the new query string.
        parts = urlsplit(point.url)
        base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        return client.request("GET", base, params=values, allow_redirects=allow_redirects)
    return client.request("POST", point.url, data=values, allow_redirects=allow_redirects)


class ActiveCheck(ABC):
    name: str = "unnamed"

    @abstractmethod
    def check_point(self, point: InjectionPoint, client: RateLimitedClient) -> list[Finding]:
        """Probe a single injection point and return any findings."""
