#!/usr/bin/env node

const PreinstallGuardian = require('./index');
const chalk = require('chalk');
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const command = args[0];

function printBanner() {
  console.log(chalk.cyan.bold('\n Preinstall Guardian\n'));
  console.log(chalk.gray('Protect your project from malicious install scripts\n'));
}

function printHelp() {
  console.log(chalk.bold('Usage:'));
  console.log('  preinstall-guardian scan [path]     Scan package.json or node_modules');
  console.log('  preinstall-guardian check           Quick check of current directory');
  console.log('  preinstall-guardian help            Show this help message\n');
  console.log(chalk.bold('Examples:'));
  console.log('  preinstall-guardian scan package.json');
  console.log('  preinstall-guardian scan node_modules');
  console.log('  preinstall-guardian check\n');
}

function printResult(result) {
  const riskColors = {
    CRITICAL: chalk.red.bold,
    HIGH: chalk.red,
    MEDIUM: chalk.yellow,
    LOW: chalk.blue,
    SAFE: chalk.green
  };

  const riskColor = riskColors[result.overallRisk] || chalk.white;
  
  console.log(riskColor(`\n ${result.packageName}@${result.version}`));
  console.log(riskColor(`   Risk Level: ${result.overallRisk}`));
  console.log(chalk.gray(`   Total Matches: ${result.totalMatches}`));

  if (result.findings.length > 0) {
    console.log(chalk.bold('\n   Findings:'));
    for (const finding of result.findings) {
      console.log(riskColor(`   • ${finding.message}`));
      
      if (finding.details && finding.details.length > 0) {
        finding.details.forEach(detail => {
          console.log(chalk.gray(`     - ${detail}`));
        });
      }

      if (finding.matches && finding.matches.length > 0 && finding.matches.length <= 5) {
        console.log(chalk.gray('     Suspicious patterns found:'));
        finding.matches.forEach(match => {
          console.log(chalk.gray(`     → ${match.matched}`));
        });
      } else if (finding.matches && finding.matches.length > 5) {
        console.log(chalk.gray(`     ${finding.matches.length} suspicious patterns found`));
      }
    }
  }
}

function printSummary(results) {
  const critical = results.filter(r => r.overallRisk === 'CRITICAL').length;
  const high = results.filter(r => r.overallRisk === 'HIGH').length;
  const medium = results.filter(r => r.overallRisk === 'MEDIUM').length;
  const low = results.filter(r => r.overallRisk === 'LOW').length;

  console.log(chalk.bold('\n Summary:'));
  console.log(chalk.gray('─'.repeat(50)));
  console.log(`   Total packages scanned: ${results.length}`);
  
  if (critical > 0) console.log(chalk.red.bold(`   CRITICAL: ${critical}`));
  if (high > 0) console.log(chalk.red(`     HIGH: ${high}`));
  if (medium > 0) console.log(chalk.yellow(`     MEDIUM: ${medium}`));
  if (low > 0) console.log(chalk.blue(`     LOW: ${low}`));
  
  console.log(chalk.gray('─'.repeat(50)));

  if (critical > 0 || high > 0) {
    console.log(chalk.red.bold('\n WARNING: High-risk packages detected!'));
    console.log(chalk.yellow('   Review these packages immediately before continuing.'));
    console.log(chalk.gray('   Consider using alternatives or pinning to known-safe versions.\n'));
    process.exit(1);
  } else if (medium > 0) {
    console.log(chalk.yellow('\n CAUTION: Medium-risk packages detected.'));
    console.log(chalk.gray('   Review these packages when possible.\n'));
  } else {
    console.log(chalk.green('\n No high-risk packages detected.\n'));
  }
}

async function main() {
  printBanner();

  const guardian = new PreinstallGuardian();

  if (!command || command === 'help') {
    printHelp();
    return;
  }

  if (command === 'scan') {
    const target = args[1] || './package.json';
    
    if (target.endsWith('package.json')) {
      console.log(chalk.gray(`Scanning ${target}...\n`));
      const result = guardian.scanPackageJson(target);
      printResult(result);
      
      if (result.overallRisk === 'CRITICAL' || result.overallRisk === 'HIGH') {
        process.exit(1);
      }
    } else {
      console.log(chalk.gray(`Scanning packages in ${target}...\n`));
      const results = guardian.scanNodeModules(target);
      
      if (results.length === 0) {
        console.log(chalk.green(' No suspicious packages found!\n'));
        return;
      }

      results.forEach(printResult);
      printSummary(results);
    }
  } else if (command === 'check') {
    console.log(chalk.gray('Running quick security check...\n'));
    
    // Check package.json
    if (fs.existsSync('./package.json')) {
      const result = guardian.scanPackageJson('./package.json');
      printResult(result);
    }

    // Check node_modules if it exists
    if (fs.existsSync('./node_modules')) {
      console.log(chalk.gray('\nScanning installed packages...\n'));
      const results = guardian.scanNodeModules('./node_modules');
      
      if (results.length > 0) {
        results.forEach(printResult);
        printSummary(results);
      } else {
        console.log(chalk.green(' No suspicious packages in node_modules!\n'));
      }
    }
  } else {
    console.log(chalk.red(`Unknown command: ${command}\n`));
    printHelp();
    process.exit(1);
  }
}

main().catch(err => {
  console.error(chalk.red('\n Error:'), err.message);
  process.exit(1);
});
