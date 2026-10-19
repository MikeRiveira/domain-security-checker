# Security Policy

## Reporting a vulnerability

Please don't open a public issue for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/MikeRiveira/domain-security-checker/security/advisories/new)
instead, and include steps to reproduce if you can. I'll reply within a few days.

## Supported versions

Security fixes go into the latest release.

## How this project stays safe

- The checker only reads public DNS, TLS and RDAP data. It never stores or sends anything else.
- TLS checks use full certificate verification.
- Dependabot keeps dependencies and GitHub Actions up to date, and CodeQL scans every change.
