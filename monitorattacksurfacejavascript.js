const { execSync } = require('child_process');
const fs = require('fs');

function scanSubdomain(subdomain) {
  const vulnerabilities = {};
  try {
    // Use Nmap to scan for open ports
    const nmapOutput = execSync(`nmap -sS -sV ${subdomain}`).toString();
    vulnerabilities['nmap'] = nmapOutput.trim();
  } catch (error) {
    vulnerabilities['nmap'] = error.message.trim();
  }
  try {
    // Use Nikto to scan for web server vulnerabilities
    const niktoOutput = execSync(`nikto -host ${subdomain}`).toString();
    vulnerabilities['nikto'] = niktoOutput.trim();
  } catch (error) {
    vulnerabilities['nikto'] = error.message.trim();
  }
  try {
    // Use Dirb to scan for directories and files
    const dirbOutput = execSync(`dirb http://${subdomain}`).toString();
    vulnerabilities['dirb'] = dirbOutput.trim();
  } catch (error) {
    vulnerabilities['dirb'] = error.message.trim();
  }
  try {
    // Use AttackSurfaceMapper to map out the attack surface
    const asmOutput = execSync(`python3 asm.py -t ${subdomain}`).toString();
    vulnerabilities['asm'] = asmOutput.trim();
  } catch (error) {
    vulnerabilities['asm'] = error.message.trim();
  }
  return vulnerabilities;
}

function scanSubdomains(subdomains) {
  const report = {};
  for (const subdomain of subdomains) {
    const vulnerabilities = scanSubdomain(subdomain);
    report[subdomain] = vulnerabilities;
  }
  return report;
}

function outputReport(report) {
  fs.writeFileSync('report.json', JSON.stringify(report, null, 4));
}

function readSubdomains(fileName) {
  const subdomains = fs.readFileSync(fileName, 'utf-8').split('\n').filter(Boolean);
  return subdomains;
}

function attackSurfaceMonitoring(subdomainsFile, intervalSeconds) {
  const subdomains = readSubdomains(subdomainsFile);
  setInterval(() => {
    const report = scanSubdomains(subdomains);
    outputReport(report);
    console.clear();
    console.log('Attack Surface Monitoring Report:');
    console.log(JSON.stringify(report, null, 4));
  }, intervalSeconds * 1000);
}

const subdomainsFile = 'subdomains.txt';
const intervalSeconds = 60 * 60; // 1 hour
attackSurfaceMonitoring(subdomainsFile, intervalSeconds);
