# TLS Certificate Inspector

A small, zero-dependency Python tool that connects to a host, completes
a TLS handshake, and reports the certificate details that matter in a
security review: expiry, issuer, subject, SANs, TLS version, and common
problems.

## What it flags

- Expired certificates, and certificates that are not valid yet
- Certificates expiring within 30 days
- Self-signed certificates (subject equals issuer)
- Verification failures, for example a hostname mismatch, with the
  underlying reason, while still describing the certificate presented
- Obsolete TLS versions (TLS 1.0 or 1.1)
- Certificates with no Subject Alternative Names

## Usage

```bash
python3 tls_inspect.py example.com
python3 tls_inspect.py example.com:8443
python3 tls_inspect.py 203.0.113.10 --server-name example.com --json
```

The expiry warning fires when a certificate has 30 days or fewer
left. Use `--warn-days` to change that horizon, for example to get a
90-day heads-up on a fleet you only review quarterly:

```bash
python3 tls_inspect.py example.com --warn-days 90
```

Example output:

```text
Host:           example.com:443
TLS version:    TLSv1.3
Subject:        commonName=example.com
Issuer:         organizationName=Example CA, commonName=Example CA Root
Expires:        2026-12-31 (213 days left)
SANs (2):       example.com, www.example.com
No problems found.
```

Exit code is 1 when a problem is found, which makes it easy to drop
into a monitoring script that alerts before a certificate expires.

## Requirements

Python 3.9 or newer. No packages to install.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Responsible use

Only inspect hosts you own or are authorised to test. The tool performs
one normal TLS handshake, the same as a browser connecting to the site.

## License

MIT, see LICENSE.
