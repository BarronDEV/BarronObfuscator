# 🔒 Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | ✅ Yes             |
| 1.x     | ❌ No              |

## Security Features

This project implements the following security measures:

### Authentication & Authorization
- BCrypt password hashing (cost factor 12)
- Session-based authentication with secure tokens
- TOTP-based Two-Factor Authentication (2FA)
- Login throttling (5 failed attempts → 15 minute lockout)
- Rate limiting (10 requests/minute per IP)

### Data Protection
- All database queries use prepared statements (SQL injection prevention)
- AES-256-GCM encryption for payment API keys in database
- Input validation and sanitization
- XSS protection via Content Security Policy headers
- 2FA secrets excluded from API responses

### Communication
- HMAC-SHA256 session token signing
- Webhook signature verification (Shopier HMAC-SHA256)
- Configurable CORS origin policy
- HTTPS/SSL support (Cloudflare Origin Certificates)

### License Protection
- Server-side key storage (keys never leave server)
- IP/HWID-based validation with auto-lock
- Grace period with SHA-256 hash integrity
- Kill switch for unauthorized usage
- Backup server failover with `valid:true` verification

## Environment Variables

> **IMPORTANT:** Never commit real credentials. Use environment variables in production.

| Variable | Purpose | Required |
|----------|---------|----------|
| `DB_HOST` | MySQL host | Yes |
| `DB_PORT` | MySQL port | No (default: 3306) |
| `DB_NAME` | Database name | No (default: barron_licenses) |
| `DB_USER` | Database username | Yes |
| `DB_PASS` | Database password | Yes |
| `BARRON_ENCRYPTION_KEY` | AES encryption passphrase for payment keys | Recommended |

## Reporting a Vulnerability

If you discover a security vulnerability, please:

1. **DO NOT** open a public issue
2. Open a private security advisory on GitHub
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact

We will respond within 48 hours.

## Best Practices for Deployment

1. **Use HTTPS** — Always deploy behind HTTPS (Cloudflare or direct SSL)
2. **Strong MySQL password** — Use complex passwords
3. **Set environment variables** — Never use default secrets in production
4. **Firewall** — Only expose necessary ports (default API: 8000, Web: 8080)
5. **Regular backups** — Enable load balancer replication
6. **Monitor logs** — Check for suspicious activity
