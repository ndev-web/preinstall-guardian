const fs = require('fs');
const path = require('path');

class PreinstallGuardian {
  constructor() {
    // Suspicious patterns found in recent attacks
    this.suspiciousPatterns = [
      // Network activity
      /fetch\s*\(/gi,
      /axios\s*\(/gi,
      /https?:\/\//gi,
      /webhook\.site/gi,
      
      // File system access
      /writeFile(Sync)?\s*\(/gi,
      /unlink(Sync)?\s*\(/gi,
      /rmdir\s*\(/gi,
      /rm\s+-rf/gi,
      
      // Shell execution
      /exec(Sync)?\s*\(/gi,
      /spawn(Sync)?\s*\(/gi,
      /child_process/gi,
      
      // Environment variable access
      /process\.env/gi,
      /\.ssh/gi,
      /\.aws/gi,
      /\.git/gi,
      
      // Token patterns
      /github.*token/gi,
      /npm.*token/gi,
      /api.*key/gi,
      
      // Obfuscation
      /eval\s*\(/gi,
      /Function\s*\(/gi,
      /Buffer\.from.*base64/gi,
      
      // Crypto hijacking
      /crypto.*wallet/gi,
      /ethereum/gi,
      /bitcoin/gi,
      
      // Bun runtime (used in Shai-Hulud 2.0)
      /setup_bun\.js/gi,
      /bun_environment\.js/gi,
    ];

    this.riskScores = {
      CRITICAL: 100,
      HIGH: 75,
      MEDIUM: 50,
      LOW: 25,
      SAFE: 0
    };
  }

  scanPackageJson(packageJsonPath) {
    if (!fs.existsSync(packageJsonPath)) {
      throw new Error(`package.json not found at ${packageJsonPath}`);
    }

    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    const results = {
      packageName: packageJson.name || 'unknown',
      version: packageJson.version || 'unknown',
      scripts: {},
      overallRisk: 'SAFE',
      totalMatches: 0,
      findings: []
    };

    // Check for lifecycle scripts
    const dangerousScripts = ['preinstall', 'install', 'postinstall', 'preuninstall', 'uninstall', 'postuninstall'];
    
    if (packageJson.scripts) {
      for (const scriptName of dangerousScripts) {
        if (packageJson.scripts[scriptName]) {
          const scriptContent = packageJson.scripts[scriptName];
          const analysis = this.analyzeScript(scriptName, scriptContent);
          results.scripts[scriptName] = analysis;
          results.totalMatches += analysis.matches.length;
        }
      }
    }

    // Determine overall risk
    results.overallRisk = this.calculateOverallRisk(results);
    results.findings = this.generateFindings(results);

    return results;
  }

  analyzeScript(scriptName, scriptContent) {
    const matches = [];
    const risks = [];

    for (const pattern of this.suspiciousPatterns) {
      const found = scriptContent.match(pattern);
      if (found) {
        matches.push({
          pattern: pattern.source,
          matched: found[0],
          context: this.getContext(scriptContent, found.index, 50)
        });
      }
    }

    // Assess risk level
    let riskLevel = 'LOW';
    if (matches.length >= 5) riskLevel = 'CRITICAL';
    else if (matches.length >= 3) riskLevel = 'HIGH';
    else if (matches.length >= 1) riskLevel = 'MEDIUM';

    // Check for specific high-risk combinations
    const hasNetwork = /fetch|axios|https?:\/\//i.test(scriptContent);
    const hasEnv = /process\.env/i.test(scriptContent);
    const hasExec = /exec|spawn|child_process/i.test(scriptContent);
    const hasObfuscation = /eval|Function\(|base64/i.test(scriptContent);

    if ((hasNetwork && hasEnv) || (hasExec && hasObfuscation)) {
      riskLevel = 'CRITICAL';
      risks.push('Combines network access with environment variable reading');
    }

    if (hasObfuscation) {
      risks.push('Uses code obfuscation techniques');
    }

    return {
      scriptName,
      scriptContent,
      matches,
      riskLevel,
      risks,
      score: this.riskScores[riskLevel]
    };
  }

  getContext(content, index, radius) {
    const start = Math.max(0, index - radius);
    const end = Math.min(content.length, index + radius);
    return content.substring(start, end);
  }

  calculateOverallRisk(results) {
    const scriptAnalyses = Object.values(results.scripts);
    if (scriptAnalyses.length === 0) return 'SAFE';

    const maxScore = Math.max(...scriptAnalyses.map(s => s.score));
    
    if (maxScore >= this.riskScores.CRITICAL) return 'CRITICAL';
    if (maxScore >= this.riskScores.HIGH) return 'HIGH';
    if (maxScore >= this.riskScores.MEDIUM) return 'MEDIUM';
    if (maxScore >= this.riskScores.LOW) return 'LOW';
    return 'SAFE';
  }

  generateFindings(results) {
    const findings = [];
    
    for (const [scriptName, analysis] of Object.entries(results.scripts)) {
      findings.push({
        type: 'lifecycle_script',
        severity: analysis.riskLevel,
        script: scriptName,
        message: `${scriptName} script detected with ${analysis.matches.length} suspicious pattern(s)`,
        details: analysis.risks,
        matches: analysis.matches
      });
    }

    return findings;
  }

  scanNodeModules(nodeModulesPath = './node_modules') {
    const results = [];
    
    if (!fs.existsSync(nodeModulesPath)) {
      return results;
    }

    const packages = fs.readdirSync(nodeModulesPath, { withFileTypes: true })
      .filter(dirent => dirent.isDirectory() && !dirent.name.startsWith('.'));

    for (const pkg of packages) {
      const packageJsonPath = path.join(nodeModulesPath, pkg.name, 'package.json');
      
      if (fs.existsSync(packageJsonPath)) {
        try {
          const scanResult = this.scanPackageJson(packageJsonPath);
          if (scanResult.overallRisk !== 'SAFE' || scanResult.totalMatches > 0) {
            results.push(scanResult);
          }
        } catch (err) {
          // Skip packages we can't scan
        }
      }

      // Handle scoped packages
      if (pkg.name.startsWith('@')) {
        const scopedPath = path.join(nodeModulesPath, pkg.name);
        const scopedPackages = fs.readdirSync(scopedPath, { withFileTypes: true })
          .filter(dirent => dirent.isDirectory());

        for (const scopedPkg of scopedPackages) {
          const packageJsonPath = path.join(scopedPath, scopedPkg.name, 'package.json');
          
          if (fs.existsSync(packageJsonPath)) {
            try {
              const scanResult = this.scanPackageJson(packageJsonPath);
              if (scanResult.overallRisk !== 'SAFE' || scanResult.totalMatches > 0) {
                results.push(scanResult);
              }
            } catch (err) {
              // Skip packages we can't scan
            }
          }
        }
      }
    }

    return results;
  }
}

module.exports = PreinstallGuardian;
