#!/usr/bin/env python3
"""
secheaders - audit the HTTP security headers, cookie flags and CORS
configuration of a website you are authorised to test.

Pure Python standard library. It sends one GET (and, with --cors, one
OPTIONS preflight) to each URL you give it. No scanning, no fuzzing,
no authentication. Only test sites you own or are permitted to assess.

Examples:
    python secheaders.py https://example.com
    python secheaders.py https://example.com --format json
    python secheaders.py https://a.example https://b.example --cors --fail-under 70
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Callable

__version__ = "1.0.0"
USER_AGENT = f"secheaders/{__version__} (+https://github.com/Zasnit1/secheaders)"


@dataclass
class Check:
    key: str
    label: str
    weight: int
    passed: bool
    present: bool
    detail: str


@dataclass
class Report:
    url: str
    status: int | None = None
    error: str | None = None
    checks: list[Check] = field(default_factory=list)

    @property
    def score(self) -> int:
        total = sum(c.weight for c in self.checks)
        got = sum(c.weight for c in self.checks if c.passed)
        return round(100 * got / total) if total else 0

    @property
    def grade(self) -> str:
        s = self.score
        for cutoff, g in ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")):
            if s >= cutoff:
                return g
        return "F"


# --------------------------------------------------------------------------- checks

def _hsts(v: str | None) -> tuple[bool, str]:
    if not v:
        return False, "missing (set Strict-Transport-Security with a long max-age)"
    try:
        age = int(next(p.split("=", 1)[1] for p in v.lower().replace(" ", "").split(";") if p.startswith("max-age=")))
    except (StopIteration, ValueError):
        return False, f"present but no valid max-age: {v!r}"
    if age < 15552000:
        return False, f"max-age={age} is below 180 days"
    return True, f"max-age={age}" + (", includeSubDomains" if "includesubdomains" in v.lower() else "")


def _csp(v: str | None) -> tuple[bool, str]:
    if not v:
        return False, "missing (a Content-Security-Policy is the strongest XSS mitigation)"
    low = v.lower()
    weak = [w for w in ("unsafe-inline", "unsafe-eval") if w in low]
    if "default-src" not in low and "script-src" not in low:
        return False, "present but defines neither default-src nor script-src"
    if weak:
        return False, "present but weakened by " + ", ".join(weak)
    return True, "present with script/default-src and no unsafe-* keywords"


def _xcto(v: str | None) -> tuple[bool, str]:
    return (v is not None and v.strip().lower() == "nosniff"), (v or "missing (expected: nosniff)")


def _frame(v: str | None, csp: str | None) -> tuple[bool, str]:
    if csp and "frame-ancestors" in csp.lower():
        return True, "covered by CSP frame-ancestors"
    if v and v.strip().lower() in ("deny", "sameorigin"):
        return True, v
    return False, (v or "missing (set X-Frame-Options or CSP frame-ancestors)")


def _refpol(v: str | None) -> tuple[bool, str]:
    safe = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin", "no-referrer-when-downgrade"}
    if v and any(p.strip().lower() in safe for p in v.split(",")):
        return True, v
    return False, (v or "missing (expected a privacy-preserving policy)")


def _ppol(v: str | None) -> tuple[bool, str]:
    return (v is not None and v.strip() != ""), (v or "missing (lock down powerful features explicitly)")


def _server(v: str | None) -> tuple[bool, str]:
    if not v:
        return True, "not disclosed"
    if any(ch.isdigit() for ch in v):
        return False, f"discloses version: {v!r}"
    return True, f"present without version: {v!r}"


HEADER_CHECKS: list[tuple[str, str, int, Callable]] = [
    ("strict-transport-security", "HSTS", 20, _hsts),
    ("content-security-policy", "Content-Security-Policy", 25, _csp),
    ("x-content-type-options", "X-Content-Type-Options", 10, _xcto),
    ("x-frame-options", "Clickjacking protection", 10, None),   # special: needs CSP too
    ("referrer-policy", "Referrer-Policy", 10, _refpol),
    ("permissions-policy", "Permissions-Policy", 10, _ppol),
    ("server", "Server banner", 5, _server),
]


def audit_headers(headers: dict[str, str]) -> list[Check]:
    g = lambda k: headers.get(k.lower())
    checks: list[Check] = []
    for key, label, weight, fn in HEADER_CHECKS:
        raw = g(key)
        if key == "x-frame-options":
            ok, detail = _frame(raw, g("content-security-policy"))
        else:
            ok, detail = fn(raw)
        checks.append(Check(key, label, weight, ok, raw is not None, detail))
    return checks


def audit_cookies(set_cookie_values: list[str]) -> list[Check]:
    checks = []
    for raw in set_cookie_values:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            continue
        for name, morsel in jar.items():
            low = raw.lower()
            missing = []
            if not morsel["secure"] and "secure" not in low:
                missing.append("Secure")
            if not morsel["httponly"] and "httponly" not in low:
                missing.append("HttpOnly")
            if "samesite" not in low:
                missing.append("SameSite")
            checks.append(Check(
                f"cookie:{name}", f"Cookie '{name}' flags", 5,
                not missing, True,
                "all of Secure/HttpOnly/SameSite set" if not missing else "missing " + ", ".join(missing),
            ))
    return checks


def audit_cors(preflight_headers: dict[str, str]) -> Check:
    origin = preflight_headers.get("access-control-allow-origin")
    creds = (preflight_headers.get("access-control-allow-credentials", "").lower() == "true")
    if origin is None:
        return Check("cors", "CORS policy", 10, True, False, "no CORS headers (same-origin only)")
    if origin == "*" and creds:
        return Check("cors", "CORS policy", 10, False, True, "wildcard origin WITH credentials: invalid and dangerous")
    if origin == "*":
        return Check("cors", "CORS policy", 10, True, True, "wildcard origin, no credentials")
    return Check("cors", "CORS policy", 10, True, True, f"reflects/sets origin: {origin!r}" + (" with credentials" if creds else ""))


# --------------------------------------------------------------------------- fetch

def fetch(url: str, method: str = "GET", timeout: float = 20.0, extra: dict | None = None) -> tuple[int, dict, list[str]]:
    headers = {"User-Agent": USER_AGENT}
    if extra:
        headers.update(extra)
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:   # 4xx/5xx still carry headers worth auditing
        resp = e
    status = resp.getcode() or (resp.status if hasattr(resp, "status") else 0)
    flat = {k.lower(): v for k, v in resp.headers.items()}
    set_cookies = resp.headers.get_all("Set-Cookie") or []
    try:
        resp.close()
    except Exception:
        pass
    return status, flat, set_cookies


def run(url: str, do_cors: bool, timeout: float) -> Report:
    if "://" not in url:
        url = "https://" + url
    r = Report(url=url)
    try:
        status, headers, cookies = fetch(url, "GET", timeout)
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        r.error = str(e)
        return r
    r.status = status
    r.checks = audit_headers(headers) + audit_cookies(cookies)
    if not url.lower().startswith("https://"):
        r.checks.insert(0, Check("https", "HTTPS", 20, False, False, "site is not served over HTTPS"))
    if do_cors:
        try:
            _, pf, _ = fetch(url, "OPTIONS", timeout,
                             {"Origin": "https://secheaders.example", "Access-Control-Request-Method": "GET"})
            r.checks.append(audit_cors(pf))
        except (urllib.error.URLError, TimeoutError, ValueError):
            pass
    return r


# --------------------------------------------------------------------------- output

def render_text(r: Report) -> str:
    if r.error:
        return f"{r.url}\n  ERROR: {r.error}"
    lines = [f"{r.url}  [HTTP {r.status}]  score {r.score}/100  grade {r.grade}"]
    for c in r.checks:
        mark = "PASS" if c.passed else "WARN"
        lines.append(f"  [{mark}] {c.label}: {c.detail}")
    return "\n".join(lines)


def render_markdown(reports: list[Report]) -> str:
    out = ["# Security headers report", "", "| Site | Score | Grade |", "|---|---|---|"]
    for r in reports:
        out.append(f"| {r.url} | {'-' if r.error else r.score} | {'-' if r.error else r.grade} |")
    for r in reports:
        out += ["", f"## {r.url}"]
        if r.error:
            out.append(f"- ERROR: {r.error}")
            continue
        for c in r.checks:
            out.append(f"- {'PASS' if c.passed else 'WARN'} **{c.label}** ({c.weight} pts): {c.detail}")
    return "\n".join(out)


def to_dict(r: Report) -> dict:
    return {"url": r.url, "status": r.status, "error": r.error, "score": r.score, "grade": r.grade,
            "checks": [vars(c) for c in r.checks]}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secheaders", description="Audit HTTP security headers, cookie flags and CORS of a site you are authorised to test.")
    p.add_argument("urls", nargs="+", help="One or more URLs or hostnames.")
    p.add_argument("--cors", action="store_true", help="Also send an OPTIONS preflight and check the CORS policy.")
    p.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--fail-under", type=int, metavar="SCORE", help="Exit with code 1 if any site scores below SCORE (for CI).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    reports = [run(u, args.cors, args.timeout) for u in args.urls]
    if args.format == "json":
        print(json.dumps([to_dict(r) for r in reports], indent=2))
    elif args.format == "markdown":
        print(render_markdown(reports))
    else:
        print("\n\n".join(render_text(r) for r in reports))
    if args.fail_under is not None and any((not r.error) and r.score < args.fail_under for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
