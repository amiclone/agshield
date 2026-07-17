# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

## Security Considerations

AntiGravity Shield is an enterprise-grade security monitoring tool. The following security measures are implemented:

### Authentication & Authorization
- **No built-in authentication**: AGShield is designed to run as a privileged system service. Access control is delegated to the operating system (Linux file permissions, Windows ACLs).
- **Privilege required**: Reading file system events requires appropriate permissions. Run as a dedicated system user.

### Data Protection
- **Hash-chained audit logs**: All detected events are appended to a SHA-256 hash-chained log file. Any tampering breaks the chain and is detected on the next verification.
- **No plaintext secrets in default config**: All sensitive values (API passwords, tokens) must be set via environment variables (`AGSHIELD_WAZUH_PASSWORD`) rather than committed to config files.
- **Sensitive values are masked**: When displaying configuration (CLI, logs), passwords and tokens are masked as `****`.

### Input Validation
- **Configuration validation**: Path-like values are checked for command-injection characters (`;`, `&`, `|`, backticks, `$`, newlines).
- **YAML parsing uses `safe_load`**: Prevents arbitrary code execution via malicious YAML.
- **Subprocess calls use explicit lists**: No `shell=True`, no string interpolation.

### File System Safety
- **Read-only baseline by default**: The Shield does not modify any monitored files (only observes them).
- **Canary files are placed in monitored directories**: They are clearly marked as decoys via filenames like `passwords_backup.txt`.
- **No background file deletion**: The Shield only observes and logs; it does not delete suspicious files.

### Network Security
- **TLS verification**: When `api_verify_ssl` is enabled (default for Wazuh API), certificate verification is enforced.
- **Configurable TLS**: Can be disabled for self-signed certificates in development environments, but defaults to **secure** mode.
- **Unix domain sockets preferred over TCP**: Local Socket communication with Wazuh agent avoids exposing traffic on the network.

### Supply Chain
- **Dependencies are pinned**: See `pyproject.toml` for exact version constraints.
- **Reproducible builds**: PyInstaller-based builds produce deterministic executables (modulo timestamps).
- **Audit bundled scripts**: The executables bundle Python + dependencies. We recommend reviewing the build scripts (`build_scripts/`) before deploying.

### Known Limitations
- **The agent scripts packaged with AGShield are intentionally malicious**: They are used for testing and demonstration. In production deployments, the agent_package should be placed in a quarantined, monitored directory.
- **Inotify limits**: Linux systems have a per-user limit on inotify watches (`/proc/sys/fs/inotify/max_user_watches`). AGShield may fail on systems with very large monitored directories without raising this limit.
- **Linux-only filesystem events**: Windows uses `ReadDirectoryChangesW` which has different semantics. Cross-platform behavior is supported but with caveats in the timestamp validation module.

## Reporting a Vulnerability

If you discover a security vulnerability in AGShield, please report it privately to:

**Email**: emmanuel.orji@example.com (replace with the actual security contact)

Please **DO NOT** open a public GitHub issue for security vulnerabilities.

Include in your report:
1. A description of the vulnerability
2. Steps to reproduce
3. Affected versions
4. Potential impact

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

## Security Best Practices for Deployment

1. **Run as a dedicated system user** (e.g., `agshield`) with minimal privileges.
2. **Restrict config file access**: `/etc/antigravity/config.yaml` should be readable only by the agshield user/group (`chmod 640`).
3. **Use environment variables for secrets**: Never commit real API credentials.
4. **Enable TLS verification** for all integrations.
5. **Monitor the audit log**: Track the hash chain integrity via the `verify_integrity()` check.
6. **Keep the executable updated**: Rebuild and redeploy periodically to incorporate security fixes.
7. **Test in isolation first**: Use a sandbox/virtual machine before production deployment.

## Compliance Notes

AGShield is designed to support:
- **GDPR**: All data is processed locally; no telemetry is sent to external services.
- **PCI-DSS**: Supports file integrity monitoring requirements.
- **NIST 800-53**: Supports AU-2 (Audit Events), AU-3 (Content of Audit Records), SI-4 (Information System Monitoring).
