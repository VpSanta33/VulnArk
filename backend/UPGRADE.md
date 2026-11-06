# Upgrade Notes

## Runtime Requirements

- Go 1.27.3 or newer.
- MySQL 8.0 or newer.

## Existing Deployments

Back up the database and configuration, then run the new binary with `-migrate`
before starting the service. Migration `2026110301` adds time-range indexes used
by analytics and audit-log retention. It is safe to rerun after an interrupted
migration.

The service removes audit records older than `audit.log_retention_days` (90 days
by default) in batches of at most 1,000 records every six hours.

## Private AI Providers

Outbound requests to AI providers and the API tester reject loopback, private,
link-local, and reserved addresses by default. Redirect destinations and DNS
results are checked as well. Each response is limited to 4 MiB, and outbound
clients do not use proxy environment variables.

To allow a private AI endpoint, configure its exact origin, including scheme and
port:

```yaml
security:
  outbound_private_origins: ["http://127.0.0.1:11434"]
```

The same setting is available through
`SECURITY_OUTBOUND_PRIVATE_ORIGINS`; separate multiple origins with commas.
Approval applies only to the configured origin. Redirects to other private
destinations remain blocked.
