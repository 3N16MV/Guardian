Welcome to Guardian - A Python-based vulnerability scanner focused on Apache version detection and CVE lookup from the National Vulnerability Database (NVD).

Features

•	Identifies open ports using Nmap. 

•	Detects Apache web servers and extracts version information from banners. 

•	Queries the NVD for known CVEs affecting discovered Apache versions. 

•	Filters vulnerabilities based on a configurable minimum CVSS score. 

•	Generates reports in HTML or JSON formats.

Installation
**Prerequisites** 

•	Python 3.11.6 or later 

•	Nmap (https://nmap.org/) 

**Installing Dependencies**

-	pip install requests
	
-	pip install python-nmap
  
-	pip install ratelimit
  
-	pip install argparse
  
**Clone the Repository**
 	
git clone https://github.com/3N16MV/Guardian.git

Usage

Guardian offers a command-line interface for easy usage:

python main.py <target> --ports <port1> <port2> ... --min-cvss <score> --output-format <json|html> --nmap-args <arguments>

Replace <target> with the system or application you wish to scan.

Example

python main.py example.com --ports 80 443 --min-cvss 8.0 --output-format HTML

Arguments

•	target (required): The hostname or IP address to scan. 

•	--ports (optional): A space-separated list of ports to scan. Defaults to 21, 22, 80, 443. 

•	--min-cvss (optional): The minimum CVSS score for vulnerabilities to include in the report. Defaults to 7.0.

•	--output-format (optional): The output format, either 'json' or 'html'. Defaults to 'json'. 

•	--nmap-args (optional): Additional arguments to be passed directly to the Nmap scan (e.g., "-sS" for SYN scan). Defaults to "-sV".Contribution

Reports

HTML Report (vulnerabilities.html) Presents vulnerabilities organized by port and service, including CVE ID, CVSS score, and a brief summary. 

JSON Report (vulnerabilities.json) Provides structured vulnerability data in JSON format for further processing or integration into other tools.

Contributions

Contributions to improve Guardian are welcomed! Feel free to open issues or submit pull requests.

License

This project is released under the MIT License. See LICENSE file for details.

Support

For any issues or questions, please contact 3n16mv@gmail.com or create an issue on GitHub.

Disclaimer

This tool is provided for educational and security testing purposes. Use responsibly on systems where you have authorization.


	
	
