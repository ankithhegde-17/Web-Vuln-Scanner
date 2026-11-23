"""webvuln-scanner: a passive, authorized-use-only web vulnerability scanner.

Phase 1 contains a same-domain crawler and passive checks only. Nothing in
this package sends attack payloads, and the HTTP client only knows how to
send GET requests.
"""

__version__ = "0.1.0"
