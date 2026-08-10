# Security policy

Reperio processes untrusted storage-media content and may expose highly sensitive recovered information. Please do not open a public issue containing a vulnerability, credential, browser record, recovered file, source-device/media identifier, or scan output.

## Reporting a vulnerability

Use the repository's [private security advisory form](https://github.com/jfrancolopez/Reperio/security/advisories/new). Include the affected revision, reproducible steps using synthetic data, the expected safety property, observed behavior, and likely impact. Remove all real personal and company data before submitting.

If a secret has entered Git history, treat it as compromised: revoke or rotate it first. Removing it from a later commit is not sufficient. Then use a coordinated history-cleanup plan if needed.

## Supported versions

Reperio is pre-release and has no supported runtime release yet. Security corrections currently target the latest revision of `main`. This policy will gain a supported-version table before the first public release.

## Security boundaries

The central guarantee is no writes to the selected source medium. Reports involving a source write, unexpected mount, optical burn/blank command, format/repair action, execution of discovered content, sandbox escape, path traversal, unauthorized LAN access, credential disclosure, unsafe preview, media-swap confusion, or destination/source identity confusion should be treated as high priority.

Reperio is a recovery and discovery tool for authorized media. It is not a forensic-certification product and does not promise recovery of overwritten, TRIM-discarded, physically unreadable, or strongly encrypted data.
