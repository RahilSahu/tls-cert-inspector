#!/usr/bin/env python3
"""TLS certificate inspector.

Connects to a host, completes a TLS handshake, and reports the details
that matter in a review: expiry, issuer, subject, SANs, TLS version and
basic problems such as an expired, not-yet-valid, or self-signed
certificate, or a hostname mismatch.

Zero dependencies: Python 3.9+ standard library only. Use it on hosts
you own or are authorised to test.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class CertReport:
    host: str
    port: int
    tls_version: str | None = None
    cipher: str | None = None
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_remaining: int | None = None
    sans: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _flatten(name_tuple) -> str:
    parts = []
    for rdn in name_tuple or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def parse_cert(cert: dict, now: datetime | None = None) -> dict:
    """Extract the useful fields from an ssl certificate dict.

    Separated from the network code so it can be unit tested with a
    fixture certificate.
    """
    now = now or datetime.now(timezone.utc)
    fmt = "%b %d %H:%M:%S %Y %Z"
    not_before = datetime.strptime(cert["notBefore"], fmt).replace(tzinfo=timezone.utc) if cert.get("notBefore") else None
    not_after = datetime.strptime(cert["notAfter"], fmt).replace(tzinfo=timezone.utc) if cert.get("notAfter") else None
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    if cert.get("subjectAltName"):
        sans += [value for kind, value in cert["subjectAltName"] if kind == "IP Address"]
    days = (not_after - now).days if not_after else None

    problems, warnings = [], []
    if not_after and now > not_after:
        problems.append(f"Certificate expired on {not_after.date().isoformat()}")
    if not_before and now < not_before:
        problems.append(f"Certificate is not valid until {not_before.date().isoformat()}")
    if days is not None and 0 <= days <= 30:
        warnings.append(f"Certificate expires in {days} days, renew soon")
    subject = _flatten(cert.get("subject"))
    issuer = _flatten(cert.get("issuer"))
    if subject and subject == issuer:
        problems.append("Certificate appears to be self-signed (subject equals issuer)")
    if not sans:
        warnings.append("Certificate has no Subject Alternative Names")

    return {
        "subject": subject, "issuer": issuer, "sans": sans,
        "not_before": not_before, "not_after": not_after,
        "days_remaining": days, "serial": str(cert.get("serialNumber", "")),
        "problems": problems, "warnings": warnings,
    }


def inspect(host: str, port: int = 443, timeout: float = 10.0, server_name: str | None = None) -> CertReport:
    report = CertReport(host=host, port=port)
    sni = server_name or host

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=sni) as tls:
                report.tls_version = tls.version()
                cipher = tls.cipher()
                report.cipher = cipher[0] if cipher else None
                parsed = parse_cert(tls.getpeercert())
    except ssl.SSLCertVerificationError as exc:
        # Verification failed (expired, self-signed, wrong host, ...).
        # Reconnect without verification so we can still describe the cert.
        report.problems.append(f"Verification failed: {exc.verify_message}")
        insecure = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with insecure.wrap_socket(raw, server_hostname=sni) as tls:
                report.tls_version = tls.version()
                cipher = tls.cipher()
                report.cipher = cipher[0] if cipher else None
                parsed = parse_cert(tls.getpeercert(binary_form=False) or _binary_cert_to_dict(tls.getpeercert(binary_form=True), host, port))
    report.subject = parsed["subject"]
    report.issuer = parsed["issuer"]
    report.serial = parsed["serial"]
    report.not_before = parsed["not_before"]
    report.not_after = parsed["not_after"]
    report.days_remaining = parsed["days_remaining"]
    report.sans = parsed["sans"]
    report.problems += [p for p in parsed["problems"] if p not in report.problems]
    report.warnings += parsed["warnings"]
    if report.tls_version in ("TLSv1", "TLSv1.1"):
        report.problems.append(f"Obsolete TLS version negotiated: {report.tls_version}")
    return report


def _binary_cert_to_dict(der: bytes, host: str, port: int) -> dict:
    """Best-effort decode for the unverified fallback path.

    ssl's test decoder reads PEM files, so convert DER to PEM first.
    """
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der))
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:
        return {}
    finally:
        os.unlink(path)


def print_report(r: CertReport) -> None:
    print(f"\nHost:           {r.host}:{r.port}")
    print(f"TLS version:    {r.tls_version}")
    print(f"Cipher:         {r.cipher}")
    print(f"Subject:        {r.subject}")
    print(f"Issuer:         {r.issuer}")
    if r.not_before:
        print(f"Valid from:     {r.not_before.date().isoformat()}")
    if r.not_after:
        print(f"Expires:        {r.not_after.date().isoformat()} ({r.days_remaining} days left)")
    print(f"SANs ({len(r.sans)}):   {', '.join(r.sans[:10])}{' ...' if len(r.sans) > 10 else ''}")
    for p in r.problems:
        print(f"[PROBLEM] {p}")
    for w in r.warnings:
        print(f"[WARNING] {w}")
    if not r.problems and not r.warnings:
        print("No problems found.")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect a TLS certificate.")
    parser.add_argument("host", help="Hostname or IP, optionally host:port")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--server-name", default=None, help="SNI name, defaults to the host")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    host, _, port_text = args.host.partition(":")
    port = args.port or (int(port_text) if port_text else 443)
    try:
        report = inspect(host, port=port, timeout=args.timeout, server_name=args.server_name)
    except (OSError, ssl.SSLError, ValueError) as exc:
        print(f"Error: could not inspect {host}:{port}: {exc}", file=sys.stderr)
        return 2

    if args.json:
        data = vars(report).copy()
        for key in ("not_before", "not_after"):
            if data[key]:
                data[key] = data[key].isoformat()
        print(json.dumps(data, indent=2))
    else:
        print_report(report)
    return 1 if report.problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
