# 🛡️ Preinstall Guardian

**Protect your project from malicious npm install scripts**

Preinstall Guardian scans npm packages for suspicious patterns in lifecycle scripts (preinstall, install, postinstall) **before** they can execute malicious code. Inspired by the 2025 Shai-Hulud and npm supply chain attacks.

## Why You Need This

In 2025, npm faced multiple devastating supply chain attacks:
- **Shai-Hulud**: Compromised 500+ packages, stealing credentials via postinstall scripts
- **Shai-Hulud 2.0**: Used **preinstall** scripts to execute before installation completes
- **Chalk/Debug attack**: 18 popular packages with 2.6B weekly downloads compromised

These attacks exploit lifecycle scripts that run automatically during `npm install`. By the time you notice something's wrong, your credentials may already be stolen.

## Features

- ✅ Scans for 25+ suspicious patterns used in real attacks
- ✅ Detects network access, file system manipulation, shell execution
- ✅ Identifies obfuscation techniques (eval, base64, Function())
- ✅ Flags environment variable access (AWS, GitHub, npm tokens)
- ✅ Risk scoring: CRITICAL, HIGH, MEDIUM, LOW, SAFE
- ✅ Zero dependencies (uses only chalk for colors)
- ✅ Fast - scans thousands of packages in seconds

## Installation

```bash
npm install -g preinstall-guardian
```

Or use without installing:

```bash
npx preinstall-guardian check
```

## Usage

### Quick security check
```bash
preinstall-guardian check
```

Scans your `package.json` and `node_modules` for suspicious scripts.

### Scan a specific package.json
```bash
preinstall-guardian scan package.json
```

### Scan all installed packages
```bash
preinstall-guardian scan node_modules
```

### Short alias
```bash
pig check  # Same as preinstall-guardian check
```

## Example Output

```
Preinstall Guardian

Protect your project from malicious install scripts

 suspicious-package@1.2.3
   Risk Level: CRITICAL
   Total Matches: 7

   Findings:
   • postinstall script detected with 7 suspicious pattern(s)
     - Combines network access with environment variable reading
     - Uses code obfuscation techniques
     Suspicious patterns found:
     → fetch(
     → process.env
     → eval(
     → child_process

   Summary:
──────────────────────────────────────────────────
   Total packages scanned: 1
    CRITICAL: 1
──────────────────────────────────────────────────

   WARNING: High-risk packages detected!
   Review these packages immediately before continuing.
```

## What It Detects

Preinstall Guardian looks for patterns commonly used in malicious packages:

### Network Activity
- HTTP requests (fetch, axios, webhooks)
- Connections to suspicious domains

### File System Access
- Writing/deleting files
- Accessing SSH keys, AWS credentials
- Home directory manipulation

### Shell Execution
- Running system commands
- Spawning child processes

### Credential Theft
- Environment variable access
- GitHub/npm token patterns
- Cloud provider credentials (AWS, GCP, Azure)

### Obfuscation
- eval() usage
- Base64 encoding
- Dynamic code execution

### Known Attack Signatures
- Bun runtime files (Shai-Hulud 2.0)
- Crypto wallet manipulation
- Specific malware patterns

## CI/CD Integration

Add to your CI pipeline to block malicious packages:

```yaml
# .github/workflows/security.yml
name: Security Check
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: npm ci
      - name: Scan for malicious scripts
        run: npx preinstall-guardian check
```

The command exits with code 1 if CRITICAL or HIGH risk packages are found.

## Use as a Library

```javascript
const PreinstallGuardian = require('preinstall-guardian');

const guardian = new PreinstallGuardian();

// Scan a single package.json
const result = guardian.scanPackageJson('./package.json');
console.log(`Risk: ${result.overallRisk}`);
console.log(`Findings: ${result.findings.length}`);

// Scan all packages in node_modules
const results = guardian.scanNodeModules('./node_modules');
const critical = results.filter(r => r.overallRisk === 'CRITICAL');
console.log(`Found ${critical.length} critical packages`);
```

## When to Use

- ✅ Before running `npm install` in a new project
- ✅ After adding new dependencies
- ✅ In CI/CD pipelines before deployment
- ✅ Regular security audits of existing projects
- ✅ When suspicious activity is detected in the npm ecosystem

## Limitations

- Does not execute code (static analysis only)
- May have false positives for legitimate use cases
- Cannot detect all obfuscation techniques
- Complements but doesn't replace tools like Socket, Snyk

## Best Practices

1. **Use with npm audit**: `npm audit && preinstall-guardian check`
2. **Pin dependencies**: Lock to specific versions after scanning
3. **Review updates carefully**: Don't auto-update without scanning
4. **Enable pnpm security features**: Disable lifecycle scripts by default
5. **Monitor advisories**: Stay informed about new attack patterns

## Recent Attack Patterns

This tool is updated to detect patterns from:
- Shai-Hulud (Sep 2025)
- Shai-Hulud 2.0 (Nov 2025)
- Chalk/Debug compromise (Sep 2025)
- Nx attack (Aug 2025)
- North Korean OtterCookie campaign (Nov 2025)

## Contributing

Found a new malicious pattern? Submit an issue or PR with details.

## License

MIT

## Disclaimer

This tool provides static analysis and risk assessment. It cannot guarantee complete protection against all threats. Always follow security best practices and stay informed about the latest vulnerabilities.

---

**Stay safe out there! **
