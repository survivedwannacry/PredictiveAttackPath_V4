# Security Policy

## Privacy

PredictiveAttackPath processes all log data **locally**. No log content is ever transmitted to external servers.

The only outbound network request is the initial download of the MITRE ATT&CK STIX dataset from `github.com/mitre-attack`. This happens once on first run and is cached locally.

The backend API listens on `127.0.0.1:8000` (localhost only) and is not accessible from the network.

## Test Logs

The test logs in `test_logs/` are **entirely simulated**. They do not contain real attack data, real IP addresses, or real credentials. All hostnames, usernames, and domains are fictional.

## Reporting Vulnerabilities

If you discover a security issue, please report it by opening a GitHub issue or contacting the maintainers directly.
