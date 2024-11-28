import nmap
import json
import os
import requests
import logging
import re
from datetime import datetime
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for more visibility
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        
    def scan_network(self, target: str, ports: str = "1-1024", arguments: str = "-sV -sC --script=vuln") -> dict:
        try:
            logger.info(f"Starting vulnerability scan of target: {target}")
            # Run initial scan
            scan_results = self.scanner.scan(hosts=target, ports=ports, arguments=arguments)
            logger.info("Basic scan complete, processing results")
            
            # Process results and gather vulnerability data
            results = self._process_results(scan_results)
            
            # Add vulnerability data to each host
            for host in results['hosts']:
                if self.shodan_api_key:
                    try:
                        self._add_shodan_vulnerabilities(host)
                    except Exception as e:
                        logger.error(f"Error getting Shodan data for {host['ip']}: {e}")
            
            return results
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return {'timestamp': datetime.now().isoformat(), 'error': str(e), 'hosts': []}

    def _process_results(self, scan_results: dict) -> dict:
        processed_results = {
            'timestamp': datetime.now().isoformat(),
            'hosts': []
        }
        
        try:
            for host_ip, host_data in scan_results['scan'].items():
                if 'status' not in host_data or host_data['status']['state'] != 'up':
                    continue
                    
                logger.debug(f"Processing host: {host_ip}")
                
                # Basic host info
                host_info = {
                    'ip': host_ip,
                    'hostname': host_data.get('hostnames', [{'name': ''}])[0].get('name', ''),
                    'state': host_data.get('status', {}).get('state', ''),
                    'mac_address': host_data.get('addresses', {}).get('mac', 'N/A'),
                    'vendor': host_data.get('vendor', {}).get(host_data.get('addresses', {}).get('mac', ''), 'N/A'),
                    'ports': [],
                    'vulnerabilities': []
                }
                
                # Process TCP ports
                if 'tcp' in host_data:
                    for port, port_info in host_data['tcp'].items():
                        port_data = {
                            'port': port,
                            'state': port_info.get('state', ''),
                            'service': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        
                        # Process vulnerability scripts
                        if 'script' in port_info:
                            scripts = port_info['script']
                            for script_name, output in scripts.items():
                                if 'vulners' in script_name or 'vuln' in script_name:
                                    self._process_vuln_script(host_info, port_data, output)
                        
                        host_info['ports'].append(port_data)
                
                # Process UDP ports if present
                if 'udp' in host_data:
                    for port, port_info in host_data['udp'].items():
                        port_data = {
                            'port': port,
                            'state': port_info.get('state', ''),
                            'service': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        host_info['ports'].append(port_data)
                
                processed_results['hosts'].append(host_info)
                
        except Exception as e:
            logger.error(f"Error processing scan results: {str(e)}")
            
        return processed_results
    
    def _process_vuln_script(self, host_info: dict, port_data: dict, script_output: str):
        """Process vulnerability script output and add findings to host_info."""
        try:
            # Track unique CVEs to avoid duplicates
            existing_cves = {vuln['cve_id'] for vuln in host_info.get('vulnerabilities', [])}
            
            # Extract CVE IDs and their CVSS scores using regex
            # Look for patterns like "CVE-2023-28450   7.5    https://vulners.com/cve/CVE-2023-28450"
            cve_pattern = r'(CVE-\d{4}-\d+)\s+(\d+\.\d+)'
            matches = re.findall(cve_pattern, script_output)
            
            for cve_id, cvss_score in matches:
                if cve_id not in existing_cves:
                    # Extract a better summary by finding the relevant section
                    summary_pattern = rf"{cve_id}.*?(?=CVE-|$)"
                    summary_match = re.search(summary_pattern, script_output, re.DOTALL)
                    summary = summary_match.group(0).strip() if summary_match else "No summary available"
                    
                    # Determine severity based on CVSS score
                    cvss = float(cvss_score)
                    severity = 'high' if cvss >= 7.0 else 'medium' if cvss >= 4.0 else 'low'
                    
                    vuln = {
                        'cve_id': cve_id,
                        'cvss_score': cvss,
                        'affected_service': f"{port_data['product']} {port_data['version']} on port {port_data['port']}",
                        'summary': summary,
                        'severity': severity
                    }
                    
                    host_info['vulnerabilities'].append(vuln)
                    existing_cves.add(cve_id)
                    logger.info(f"Found vulnerability {cve_id} (CVSS: {cvss}) for {host_info['ip']}")
                    
        except Exception as e:
            logger.error(f"Error processing vulnerability script: {e}")

    def _add_shodan_vulnerabilities(self, host_info: dict):
        """Add vulnerability information from Shodan."""
        try:
            existing_cves = {vuln['cve_id'] for vuln in host_info.get('vulnerabilities', [])}
            
            response = requests.get(
                f"https://api.shodan.io/shodan/host/{host_info['ip']}?key={self.shodan_api_key}",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if 'vulns' in data:
                    logger.info(f"Found Shodan vulnerabilities for {host_info['ip']}")
                    for cve_id, vuln_data in data['vulns'].items():
                        if cve_id not in existing_cves:
                            cvss = float(vuln_data.get('cvss', 5.0))
                            vuln = {
                                'cve_id': cve_id,
                                'cvss_score': cvss,
                                'summary': vuln_data.get('summary', 'No summary available'),
                                'severity': 'high' if cvss >= 7.0 else 'medium' if cvss >= 4.0 else 'low',
                                'source': 'Shodan'
                            }
                            host_info['vulnerabilities'].append(vuln)
                            existing_cves.add(cve_id)
        except Exception as e:
            logger.error(f"Error getting Shodan data: {e}")

    def generate_html_report(self, results: dict, output_file: str) -> None:
        try:
            logger.info(f"Generating report to {output_file}")
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Network Security Scan Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    .host-section {{ margin-bottom: 30px; padding: 20px; border: 1px solid #eee; }}
                    .timestamp {{ color: #666; margin-bottom: 20px; }}
                    .vulnerability {{ background-color: #fff3f3; padding: 10px; margin: 5px 0; }}
                    .high-severity {{ border-left: 5px solid #ff4444; }}
                    .medium-severity {{ border-left: 5px solid #ffaa33; }}
                    .low-severity {{ border-left: 5px solid #ffdd33; }}
                    .ssl-info {{ background-color: #f8f9fa; padding: 10px; margin: 5px 0; }}
                </style>
            </head>
            <body>
                <h1>Network Security Scan Report</h1>
                <div class="timestamp">Scan performed at: {results['timestamp']}</div>
            """

            for host in results['hosts']:
                html_content += self._generate_host_section(host)

            html_content += """
            </body>
            </html>
            """
            
            # Ensure output directory exists
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            logger.info(f"Report generated successfully at {output_file}")
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            raise

    def _generate_host_section(self, host: dict) -> str:
        section = f"""
            <div class="host-section">
                <h2>Host: {host['ip']}</h2>
                <p>Hostname: {host['hostname']}</p>
                <p>State: {host['state']}</p>
                <p>MAC Address: {host['mac_address']}</p>
                <p>Vendor: {host['vendor']}</p>
                
                <h3>Open Ports and Services:</h3>
                <table>
                    <tr>
                        <th>Port</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Product</th>
                        <th>Extra Info</th>
                    </tr>
        """
        
        # Add port information
        for port in sorted(host['ports'], key=lambda x: int(x['port'])):
            section += f"""
                    <tr>
                        <td>{port['port']}</td>
                        <td>{port['state']}</td>
                        <td>{port['service']}</td>
                        <td>{port['version']}</td>
                        <td>{port['product']}</td>
                        <td>{port['extrainfo']}</td>
                    </tr>
            """
        
        section += "</table>"
        
        # Add vulnerabilities if found
        if host.get('vulnerabilities'):
            section += "\n<h3>Identified Vulnerabilities:</h3>"
            for vuln in host['vulnerabilities']:
                severity = vuln.get('severity', 'medium')
                section += f"""
                <div class="vulnerability {severity}-severity">
                    <h4>{vuln['cve_id']}</h4>
                    <p>CVSS Score: {vuln.get('cvss_score', 'N/A')}</p>
                    <p>Affected Service: {vuln.get('affected_service', 'Unknown')}</p>
                    <p>Summary: {vuln['summary']}</p>
                </div>
                """
        
        section += "</div>"
        return section

def main():
    try:
        # Get configuration from environment variables
        target = os.getenv("NMAP_TARGET", "192.168.1.0/24")
        ports = os.getenv("NMAP_PORTS", "1-65535")
        arguments = os.getenv("NMAP_ARGS", "-sV -sC --script=vuln")
        output_file = os.getenv("NMAP_REPORT", "nmap_report.html")
        
        logger.info("Starting vulnerability scan")
        scanner = VulnerabilityScanner()
        results = scanner.scan_network(target, ports, arguments)
        scanner.generate_html_report(results, output_file)
        
        logger.info("Scan and report completed successfully")
        
    except Exception as e:
        logger.error(f"Fatal error in main: {e}")
        raise

if __name__ == "__main__":
    main()