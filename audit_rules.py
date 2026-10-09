"""The eight security-header checks, their weights and the grade.

Same rules and wording as the portfolio site's TypeScript version, so both give the same result.
"""

import re
from typing import Callable


def _first(value):
    if isinstance(value, list):
        return ", ".join(value)
    return value or None


def _hsts(h, is_https):
    value = _first(h.get("strict-transport-security"))
    if not is_https:
        return "fail", value, "The page was served over plain HTTP, so HSTS cannot apply."
    if not value:
        return "fail", value, "Missing. Browsers may still try HTTP first."
    match = re.search(r"max-age=(\d+)", value, re.I)
    age = int(match.group(1)) if match else 0
    if age < 15552000:
        return "warn", value, f"max-age is {age}s; aim for at least 180 days (15552000s), ideally 1 year."
    return "pass", value, "Present with a long max-age."


def _csp(h, is_https):
    value = _first(h.get("content-security-policy"))
    if not value:
        return "fail", value, "Missing. Injected scripts would run freely."
    weak = []
    if re.search(r"'unsafe-inline'", value, re.I):
        weak.append("'unsafe-inline'")
    if re.search(r"'unsafe-eval'", value, re.I):
        weak.append("'unsafe-eval'")
    if re.search(r"(^|[;\s])(default-src|script-src)[^;]*\s\*(\s|;|$)", value, re.I):
        weak.append("a wildcard source")
    if weak:
        return "warn", value, f"Present, but weakened by {' and '.join(weak)}."
    return "pass", value, "Present without the common weaknesses."


def _xfo(h, is_https):
    value = _first(h.get("x-frame-options"))
    csp = _first(h.get("content-security-policy")) or ""
    if value and re.fullmatch(r"deny|sameorigin", value.strip(), re.I):
        return "pass", value, "Framing is restricted."
    if re.search(r"frame-ancestors", csp, re.I):
        return "pass", value, "Covered by the CSP frame-ancestors directive."
    if value:
        return "warn", value, "Present, but not DENY or SAMEORIGIN."
    return "fail", value, "Missing. The page can be framed by any site."


def _xcto(h, is_https):
    value = _first(h.get("x-content-type-options"))
    if value and re.search(r"nosniff", value, re.I):
        return "pass", value, "MIME sniffing is disabled."
    return "fail", value, "Missing or not set to nosniff."


def _referrer(h, is_https):
    value = _first(h.get("referrer-policy"))
    if not value:
        return "warn", value, "Missing. Modern browsers default to a reasonable policy, but it's better to set one."
    if re.search(r"unsafe-url", value, re.I):
        return "warn", value, "unsafe-url sends the full address everywhere."
    return "pass", value, "A referrer policy is set."


def _permissions(h, is_https):
    value = _first(h.get("permissions-policy"))
    if value:
        return "pass", value, "Browser features are restricted."
    return "warn", value, "Missing. All features stay at browser defaults."


def _leak(h, is_https):
    powered = _first(h.get("x-powered-by"))
    server = _first(h.get("server"))
    leaks = []
    if powered:
        leaks.append(f"X-Powered-By: {powered}")
    if server and re.search(r"\d+(\.\d+)+|/\d", server):
        leaks.append(f"Server: {server}")
    if leaks:
        return "warn", "; ".join(leaks), "Software details are exposed."
    return "pass", server, "No obvious version banners."


def _cookies(h, is_https):
    raw = h.get("set-cookie")
    cookies = raw if isinstance(raw, list) else ([raw] if raw else [])
    if not cookies:
        return "pass", None, "No cookies set on this response."
    weak = [
        c
        for c in cookies
        if not re.search(r";\s*secure", c, re.I)
        or not re.search(r";\s*httponly", c, re.I)
        or not re.search(r";\s*samesite=", c, re.I)
    ]
    if not weak:
        return "pass", f"{len(cookies)} cookie(s)", "All cookies carry Secure, HttpOnly and SameSite."
    return "warn", f"{len(weak)} of {len(cookies)} cookie(s) are missing flags", "Some cookies lack Secure, HttpOnly or SameSite."


# id, name, weight, why it matters, how to fix, check function
_RULES: list[tuple[str, str, int, str, str, Callable]] = [
    ("hsts", "Strict-Transport-Security", 20,
     "Tells browsers to only ever use HTTPS for this site, which blocks downgrade and cookie-stealing attacks on public Wi-Fi.",
     "Send Strict-Transport-Security: max-age=31536000; includeSubDomains (once every subdomain supports HTTPS).",
     _hsts),
    ("csp", "Content-Security-Policy", 25,
     "Limits where scripts, styles and frames can load from, which is the strongest browser-side defence against cross-site scripting (XSS).",
     "Define a policy such as default-src 'self' and avoid 'unsafe-inline', 'unsafe-eval' and wildcards in script-src.",
     _csp),
    ("xfo", "X-Frame-Options", 15,
     "Stops other sites from embedding this page in a hidden frame to trick users into clicking (clickjacking).",
     "Send X-Frame-Options: DENY (or SAMEORIGIN), or use a CSP frame-ancestors directive.",
     _xfo),
    ("xcto", "X-Content-Type-Options", 15,
     "Stops browsers guessing a file's type, so an uploaded file can't be reinterpreted as a script.",
     "Send X-Content-Type-Options: nosniff.",
     _xcto),
    ("referrer", "Referrer-Policy", 10,
     "Controls how much of the page address is sent to other sites when users follow a link, which can otherwise leak private paths or tokens.",
     "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
     _referrer),
    ("permissions", "Permissions-Policy", 5,
     "Switches off powerful browser features (camera, microphone, location) the site doesn't need, including inside embedded frames.",
     "Send Permissions-Policy: camera=(), microphone=(), geolocation=() and allow only what you use.",
     _permissions),
    ("leak", "Server information leaks", 5,
     "Version banners tell attackers exactly which software to look up known exploits for.",
     "Remove X-Powered-By and hide version numbers in the Server header.",
     _leak),
    ("cookies", "Cookie flags", 5,
     "Secure keeps cookies off plain HTTP, HttpOnly hides them from scripts, and SameSite limits cross-site request forgery (CSRF).",
     "Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies.",
     _cookies),
]


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def audit(headers: dict, is_https: bool) -> dict:
    """Run every check. `headers` has lowercase names; repeated headers (set-cookie) are lists."""
    score = 0.0
    checks = []
    for rule_id, name, weight, why, fix, run in _RULES:
        status, value, summary = run(headers, is_https)
        score += weight if status == "pass" else weight / 2 if status == "warn" else 0
        checks.append(
            {"id": rule_id, "name": name, "status": status, "value": value, "summary": summary, "why": why, "fix": fix}
        )
    total = int(score + 0.5)  # round half up, like Math.round in the TypeScript version
    return {"score": total, "grade": grade(total), "checks": checks}
