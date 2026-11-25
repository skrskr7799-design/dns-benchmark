# v0.3.0 — Obsidian Signature (pre-release)

Verified source: 640ae07538f96bbc97605a6b38565b351b8a7684, CI 45607046961. Docker manifest SHA-256: 65a29fd3276117b2e2cbba4ae8cfb8ed3540c3449e54fc7802a80827d9697117. Version promotion workflow publishes the exact tested image; it does not rebuild it or mark it stable. Existing edge deployment can be updated using the already-published edge image or exact source SHA tag; versioned tag is available only after promotion succeeds.

## Existing CasaOS instance

Stop the old container, back up its complete data directory, and ensure the existing /data mount is writable by UID/GID 10001. Set an owner password (16–256 characters) via the existing owner-password file (0600, UID 10001) or NDC_OWNER_PASSWORD. For trusted LAN HTTP only, set NDC_SECURE_COOKIE=0; use verified HTTPS and secure cookies elsewhere. Preserve 8099:8080 and the existing /DATA/AppData/dns-benchmark:/data mapping. Allow only explicitly authorized DNS targets using NDC_ALLOWED_CIDRS (for example 192.168.0.108/32). No new public port or privileged mode is required. Recreate/update the container using the new image. Do not run two instances on the same directory. New schema migrations may run at startup; do not downgrade a migrated database without restoring the backup. See README and REL-01.md.

No server deployment has been performed. Full live acceptance and visual feedback remain open.
