# ssl-cert-checker

A tiny command line tool that checks the TLS/SSL certificate expiry date for one
or more hostnames and warns you before they expire. Zero dependencies. Just the
Python 3 standard library.

Useful for homelab operators, busy admins, and anyone who has ever woken up to a
website that suddenly shows a scary red warning page.

## Features

- Checks one or many hostnames in a single command
- Configurable warning window (default: 30 days)
- Reads hostnames from arguments or from stdin
- Optional JSON output for piping into other tools
- Sensible exit codes for scripting and cron jobs
- No third party packages, no virtualenv required

## Installation

No build step. You only need Python 3.7 or newer.

Option 1: download the single file directly.

```sh
curl -O https://raw.githubusercontent.com/cappy-dev/ssl-cert-checker/main/ssl_cert_checker.py
chmod +x ssl_cert_checker.py
```

Option 2: clone the repo.

```sh
git clone https://github.com/cappy-dev/ssl-cert-checker.git
cd ssl-cert-checker
```

That is it. No pip install, no requirements.txt.

## Usage

Check a single host.

```sh
python3 ssl_cert_checker.py example.com
```

Check several hosts at once.

```sh
python3 ssl_cert_checker.py example.com github.com www.google.com
```

Warn when a certificate expires within 14 days.

```sh
python3 ssl_cert_checker.py --days 14 example.com
```

Check a non standard port (for example, a self hosted service on port 8443).

```sh
python3 ssl_cert_checker.py home.example.com --port 8443
```

Read hostnames from a file, one per line, and send the output to a log.

```sh
cat my_hosts.txt | python3 ssl_cert_checker.py --stdin >> /var/log/cert-check.log
```

The short `-` form also works to read from stdin.

```sh
echo example.com | python3 ssl_cert_checker.py -
```

Get machine readable JSON output.

```sh
python3 ssl_cert_checker.py --json example.com
```

Example JSON record:

```json
[
  {
    "host": "example.com",
    "port": 443,
    "status": "ok",
    "subject": "CN=example.com",
    "issuer": "CN=R3, O=Let's Encrypt, C=US",
    "not_before": "2026-06-01T00:00:00Z",
    "not_after": "2026-08-31T00:00:00Z",
    "days_remaining": 36,
    "message": "Certificate valid for 36 more day(s)."
  }
]
```

## Exit codes

The exit code is designed to be easy to use in shell scripts, cron jobs, and
monitoring hooks.

- `0` all certificates are fine and outside the warning window
- `1` at least one certificate is expired or inside the warning window
- `2` at least one host could not be checked at all (DNS failure, connection
  refused, TLS handshake error)

This makes it trivial to wire into cron or a healthcheck endpoint.

```sh
#!/bin/sh
# /etc/cron.daily/check-certs
python3 /opt/ssl-cert-checker/ssl_cert_checker.py --days 21 \
    home.example.com cloud.example.com git.example.com \
    || echo "A certificate is close to expiry!" | mail -s "Cert alert" ops@example.com
```

## Sample output

Plain text mode is friendly to read at a glance.

```text
[OK] example.com:443
  subject : CN=example.com
  issuer  : CN=R3, O=Let's Encrypt, C=US
  expires: 2026-08-31T00:00:00Z
  days   : 36
  detail : Certificate valid for 36 more day(s).

[EXPIRED] stale.example.com:443
  subject : CN=stale.example.com
  issuer  : CN=R3, O=Let's Encrypt, C=US
  expires: 2026-07-01T00:00:00Z
  days   : -25
  detail : Certificate expired 25 day(s) ago.
```

## How it works

The script opens a standard TLS connection to each host on the chosen port and
reads the peer certificate that the server presents. It then converts the
`notBefore` and `notAfter` dates into UTC and compares them against the current
time. No data is sent over the wire; the connection is closed as soon as the
certificate has been read.

Because it only reads the certificate the server offers, it also handles
self-signed certificates without complaining. The `check_hostname` and certificate
chain verification are intentionally disabled so the report still tells you the
real expiry date. This is a reporting tool, not a hardening audit. For full chain
validation use a dedicated scanner like `testssl.sh` or `sslyze`.

## License

MIT. See the LICENSE file for details.
