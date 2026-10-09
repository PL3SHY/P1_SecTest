"""Checks for the auditor. Run with:  python test_audit.py   (or: pytest)"""

import asyncio

from audit_rules import audit, grade
from safe_fetch import BlockedAddressError, FetchFailedError, fetch_headers, is_blocked_ip, validate_url

# (address, should it be blocked?)
ADDRESS_CASES = [
    # public IPv4 / IPv6: allowed
    ("8.8.8.8", False), ("93.184.216.34", False), ("104.20.23.154", False), ("20.205.243.166", False),
    ("1.1.1.1", False), ("172.32.0.1", False), ("2606:4700::1111", False), ("2001:4860:4860::8888", False),
    ("::ffff:8.8.8.8", False),
    # private / local / reserved: blocked
    ("127.0.0.1", True), ("10.1.2.3", True), ("172.16.0.1", True), ("192.168.1.1", True),
    ("169.254.169.254", True), ("100.64.0.1", True), ("0.0.0.0", True), ("224.0.0.1", True),
    ("255.255.255.255", True), ("::1", True), ("::", True), ("fe80::1", True), ("fc00::1", True),
    ("fd12:3456::1", True), ("ff02::1", True), ("64:ff9b::7f00:1", True),
    # private addresses hiding inside IPv6
    ("::ffff:127.0.0.1", True), ("::ffff:7f00:1", True), ("::ffff:10.0.0.1", True),
    ("::ffff:169.254.169.254", True),
    # not an IP at all
    ("not-an-ip", True),
]

URL_CASES_BLOCKED = [
    "ftp://example.com", "file:///etc/passwd", "http://user:pass@example.com",
    "http://example.com:8080", "http://example.com:22", "http:///nohost",
]


def test_ip_blocklist():
    wrong = [(a, exp) for a, exp in ADDRESS_CASES if is_blocked_ip(a) != exp]
    assert not wrong, f"wrong results: {wrong}"


def test_url_validation():
    for url in URL_CASES_BLOCKED:
        try:
            validate_url(url)
        except BlockedAddressError:
            continue
        raise AssertionError(f"should have been blocked: {url}")
    validate_url("https://example.com/path?q=1")  # fine


def test_dns_name_pointing_at_localhost_is_blocked():
    # localtest.me is a real public name that resolves to 127.0.0.1
    try:
        asyncio.run(fetch_headers("http://localtest.me"))
    except BlockedAddressError:
        return
    except FetchFailedError:
        return  # offline machine: nothing to resolve, still not reachable
    raise AssertionError("a name that resolves to 127.0.0.1 must be blocked")


GOOD = {
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}


def test_perfect_headers_get_an_A():
    result = audit(GOOD, True)
    assert result["score"] == 100 and result["grade"] == "A"


def test_empty_headers_fail():
    result = audit({}, True)
    assert result["grade"] == "F"
    assert {c["id"]: c["status"] for c in result["checks"]}["csp"] == "fail"


def test_plain_http_fails_hsts():
    assert {c["id"]: c["status"] for c in audit(GOOD, False)["checks"]}["hsts"] == "fail"


def test_weak_csp_and_short_hsts_warn():
    weak = {**GOOD, "content-security-policy": "default-src 'self' 'unsafe-inline'", "strict-transport-security": "max-age=100"}
    status = {c["id"]: c["status"] for c in audit(weak, True)["checks"]}
    assert status["csp"] == "warn" and status["hsts"] == "warn"


def test_version_banner_and_loose_cookies_warn():
    h = {**GOOD, "server": "nginx/1.18.0", "set-cookie": ["id=1; Path=/"]}
    status = {c["id"]: c["status"] for c in audit(h, True)["checks"]}
    assert status["leak"] == "warn" and status["cookies"] == "warn"


def test_grade_boundaries():
    assert [grade(s) for s in (100, 90, 89, 80, 79, 65, 64, 50, 49, 0)] == list("AABBCCDDFF")


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"ok    {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
