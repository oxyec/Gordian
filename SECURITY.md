# Security policy

Gordian is a pre-release, single-operator security analysis tool. It is not a multi-tenant service or an execution sandbox. Run it with least privilege, on loopback or a restricted network, using an independently generated `GORDIAN_API_KEY`. Do not expose scanner control endpoints to the public internet.

Use GitHub's **Report a vulnerability** feature for private disclosure when enabled on the published repository. If it is unavailable, open an issue asking for a private reporting channel without including secrets, target identities or exploit details. No response-time guarantee is currently offered.

Reports, screenshots, target lists, provider credentials, local configuration, audit working files and scan databases are private artifacts. Never attach them to a public issue without review and redaction. Rotate any real credential ever committed; deleting a file does not remove Git history.

The React dashboard is a demonstration UI. Use the authenticated API/Go TUI for scans. Scope validation checks submitted and discovered targets, but third-party tool behavior, redirects and DNS changes require egress restrictions appropriate to the engagement.

Only the current development branch is maintained. Audit dependencies and use a patched Go toolchain before building a release.

## Secret leak response (required before public release)

1. Scan working tree: `gitleaks dir . --config .gitleaks.toml --redact`.
2. Scan all history: `gitleaks git . --config .gitleaks.toml --redact --log-opts=--all`.
3. If a real secret is found: rotate/revoke immediately, then rewrite Git history to remove the secret before publishing.
4. Re-run both scans and confirm clean results before proceeding.

False positives must be handled with minimal, path- or value-specific allowlist entries in `.gitleaks.toml`; never disable scanning globally.
