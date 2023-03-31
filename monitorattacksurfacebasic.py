# Project Name: Subdomain Scanner and Vulnerability Analyzer

# Project Description: The goal of this project is to build a tool that can scan a website's subdomains and analyze them for potential vulnerabilities. The tool will use Kali Linux tools to scan for vulnerabilities and produce a report of any issues found.
# This script does not require AttackSurfaceMapper installed.

import subprocess
import json
import os

def scan_subdomain(subdomain):
    vulnerabilities = {}
    try:
        # Use Nmap to scan for open ports
        nmap_output = subprocess.check_output(['nmap', '-sS', '-sV', subdomain])
        vulnerabilities['nmap'] = nmap_output.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        vulnerabilities['nmap'] = str(e)
    try:
        # Use Nikto to scan for web server vulnerabilities
        nikto_output = subprocess.check_output(['nikto', '-host', subdomain])
        vulnerabilities['nikto'] = nikto_output.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        vulnerabilities['nikto'] = str(e)
    try:
        # Use Dirb to scan for directories and files
        dirb_output = subprocess.check_output(['dirb', 'http://' + subdomain])
        vulnerabilities['dirb'] = dirb_output.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        vulnerabilities['dirb'] = str(e)
    return vulnerabilities

def scan_subdomains(subdomains):
    report = {}
    for subdomain in subdomains:
        vulnerabilities = scan_subdomain(subdomain)
        report[subdomain] = vulnerabilities
    return report

def output_report(report):
    with open('report.json', 'w') as f:
        json.dump(report, f, indent=4)

def read_subdomains(file_name):
    with open(file_name, 'r') as f:
        return f.read().splitlines()

def attack_surface_monitoring(subdomains_file, interval_seconds):
    subdomains = read_subdomains(subdomains_file)
    while True:
        report = scan_subdomains(subdomains)
        output_report(report)
        os.system('clear')
        print('Attack Surface Monitoring Report:')
        print(json.dumps(report, indent=4))
        time.sleep(interval_seconds)

subdomains_file = 'subdomains.txt'
interval_seconds = 60 * 60  # 1 hour
attack_surface_monitoring(subdomains_file, interval_seconds)
