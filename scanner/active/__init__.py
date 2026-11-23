"""Active (intrusive) checks.

Unlike the passive checks in scanner/checks/, these send crafted input to the
target and look at how it responds. Everything here is still NON-DESTRUCTIVE:
the payloads are detection probes only. They never delete, modify or submit
real data, and the client they use can only send GET and POST.

Active checks run only when the user passes BOTH --i-have-permission and
--active.
"""

from scanner.active.redirect import OpenRedirectCheck
from scanner.active.sqli import SQLInjectionCheck
from scanner.active.xss import ReflectedXSSCheck


def active_checks():
    """The active checks the scanner runs, in order."""
    return [ReflectedXSSCheck(), SQLInjectionCheck(), OpenRedirectCheck()]
