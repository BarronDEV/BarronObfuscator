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
- Rate limiting (10 requests/minute per IP)

### Data Protection
- All database queries use prepared statements (SQL injection prevention)
- Input validation and sanitization
- XSS protection via Content Security Policy headers

### Communication
- ECDH P-384 key exchange for license validation
- AES-256-GCM encryption for sensitive data
- HTTPS recommended for production

### License Protection
- Server-side key storage (keys never leave server)
- IP-based validation (max 2 IPs per license)
- Challenge-response authentication

## Reporting a Vulnerability

If you discover a security vulnerability, please:

1. **DO NOT** open a public issue
2. Email: [your-email@example.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact

We will respond within 48 hours.

## Best Practices for Deployment

1. **Use HTTPS** - Always deploy behind HTTPS
2. **Strong MySQL password** - Use complex passwords
3. **Firewall** - Only expose necessary ports (default: 7742)
4. **Regular backups** - Enable load balancer replication
5. **Monitor logs** - Check for suspicious activity
