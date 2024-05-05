#
# Alexis '3N16MV' Lariviere
# 04MAY2024
# 'Guardian' Vulnerability Scanner
# Written in Python 3.11.6 using PyCharm
#

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
# See PyCharm help at https://www.jetbrains.com/help/pycharm/

# Import necessary libraries
import socket
import requests
import nmap
import re
import json
import time
import argparse
from ratelimit import limits, sleep_and_retry

# Constants
NVD_RATE_LIMIT = 5 # NVD allows up to 5 requests per 30 seconds
RATE_LIMIT_COOLDOWN = 30 # Cooldown time for ratelimiting in seconds

# Classes
class Vulnerability:
    def __init__(self, service, version, cve_id, summary, cvss_score):
        self.service = service
        self.version = version
        self.cve_id = cve_id
        self.summary = summary
        self.cvss_score = cvss_score

    def __repr__(self):
        return f"Vulnerability({self.cve_id}, {self.service}, {self.version}, {self.cvss_score})"

class Scanner:
    def __init__(self, target, ports, min_cvss, nmap_args):
        self.target = target
        self.ports = ports
        self.min_cvss = min_cvss
        self.nmap_args = nmap_args
        self.nm = nmap.PortScanner()

    def scan(self):
        vulnerabilities = []
        try:
            self.nm.scan(self.target, arguments=self.nmap_args)
            if self.target not in self.nm.all_hosts():
                print(f"Host {self.target} not found in scan results.")
                return vulnerabilities
        except Exception as e:
            print(f"Error while scanning {self.target}: {e}")
            return vulnerabilities

        for port in self.ports:
            if port in self.nm[self.target]['tcp']:
                vulnerabilities += self.scan_port(port)
        return vulnerabilities

    def scan_port(self, port):
        vulnerabilities = []
        try:
            sock = socket.create_connection((self.target, port), timeout=2)
            banner = sock.recv(1024).decode().strip()
            print(f"Port {port} open. Banner: {banner}")
            vulnerabilities = self.check_vulnerabilities(banner)
            sock.close()
        except (socket.timeout, ConnectionRefusedError):
            print(f"Port {port} is closed or timed out.")
        except socket.error as e:
            print(f"Socket error on port {port}: {e}")
        return vulnerabilities

    def check_vulnerabilities(self, banner):
        vulnerabilities = []
        apache_match = re.search(r"Apache/(\d\.\d+)", banner)
        if apache_match:
            version = apache_match.group(1)
            nvd_results = query_nvd(f"Apache {version}")
            for cve in nvd_results:
                cvss_score = cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 0)
                if cvss_score >= self.min_cvss:
                    vulnerabilities.append(Vulnerability(
                        "Apache", version, cve['cve'], cve['CVE_data_meta']['ID'], cve['cve']['description']['description_data'][0]['value'], cvss_score
                    ))
        return vulnerabilities

# Functions
@sleep_and_retry
@limits(calls=NVD_RATE_LIMIT, period=RATE_LIMIT_COOLDOWN)

def query_nvd(query):
    base_url = "https://service.nvd.nist.gov/rest/json/cves/1.0"
    response = requests.get(base_url, params={'keyword' f"{query}"})
    if response.status_code == 200:
        return response.json()['result']['CVE_Items'] # Check NVD Docs
    elif response.status_code == 400:
        print("Bad request to the NVD API.")
    elif response.status_code == 403:
        print("Access forbidden to the NVD API.")
    elif response.status_code == 429:
        print(f"Rate limit exceeded. Waiting {RATE_LIMIT_COOLDOWN} seconds...")
        time.sleep(RATE_LIMIT_COOLDOWN)
    elif response.status_code == 500:
        print("Internal server error the NVD API.")
    else:
        print(f"Error querying NVD: {response.status_code} - {response.reason}")
    return[]

# Export Reporting
def export_html_report(vulns, filename ="vulnerabilities.html"):
    with open(filename, "w") as f:
        f.write("<html><body>")
        f.write("<h1><body>")
        for vuln in vulns:
            f.write(f"<h2>{vulns.service} {vulns.version} - {vulns.cve_id}</h2>")
            f.write(f"<p>CVSS Score: {vulns.cvss_score}<p/>")
            f.write(f"<p>{vulns.summary}<p/>")
    f.write("</body></html>")

def export_json_report(vulns, filename="vulnerabilities.json"):
    with open(filename, "w") as f:
        json.dump([v.__dict__ for v in vulns], f, indent=4)

# Main Script
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Guardian Vulnerability Scanner')
    parser.add_argument('target', type=str, help='Target to scan')
    parser.add_argument('--ports', type=int, nargs='+', default=[21, 22, 80, 443], help='Ports to scan')
    parser.add_argument('--min-cvss', type=float, default=7.0, help='Minimum CVSS score to include in report')
    parser.add_argument('--output-format', choices=['json', 'html'], default='json', help='Output format for the report')
    parser.add_argument('--nmap-args', type=str, default="-sV", help='Nmap arguments for the scan')
    args = parser.parse_args()

    scanner = Scanner(args.target, args.ports, args.min_cvss, args.nmap_args)
    vulnerabilities = scanner.scan()

    if args.output_format == 'html':
        export_html_report(vulnerabilities)
    else:
        export_json_report(vulnerabilities)



