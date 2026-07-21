# Security Policy

## Reporting a vulnerability

Do not report security vulnerabilities through public issues. Email the repository owner directly with a concise description, reproduction steps, affected versions, and any suggested remediation.

We will acknowledge a report within five business days and coordinate a fix and disclosure timeline with the reporter.

## Deployment guidance

Transport Lookout runs network-scanning workers and must be deployed only for networks you are authorized to assess. Production deployments must disable bootstrap authentication, configure OIDC, use TLS, keep credentials in a secrets manager, and isolate worker network access.

