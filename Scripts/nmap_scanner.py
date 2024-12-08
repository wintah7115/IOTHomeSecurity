import nmap
import json
import os
import requests
import logging
import re
from datetime import datetime
from pathlib import Path

# Set up logging configuration for tracking scan progress and debugging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    """
    A network vulnerability scanner that combines Nmap scanning with Shodan data.
    Performs comprehensive network scanning and vulnerability assessment.
    """
    
    def __init__(self):
        # Initialize Nmap scanner and get Shodan API key from environment
        self.scanner = nmap.PortScanner()
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        
    def scan_network(self, target: str, ports: str = "1-1024", arguments: str = "-sV -sC --script=vuln") -> dict:
        """
        Perform a network vulnerability scan using Nmap.
        
        Args:
            target: IP address or range to scan (e.g., '192.168.1.0/24')
            ports: Port range to scan (e.g., '1-1024')
            arguments: Nmap scan arguments (e.g., '-sV -sC --script=vuln')
            
        Returns:
            dict: Processed scan results including host information and vulnerabilities
        """
        try:
            logger.info(f"Starting vulnerability scan of target: {target}")
            # Execute Nmap scan with specified parameters
            scan_results = self.scanner.scan(hosts=target, ports=ports, arguments=arguments)
            logger.info("Basic scan complete, processing results")
            
            # Convert raw Nmap results into structured data
            results = self._process_results(scan_results)
            
            # Include Shodan vulnerability information if API key available
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
        """
        Process raw Nmap scan results into a structured format.
        Extracts host information, port data, and vulnerability findings.
        
        Args:
            scan_results: Raw Nmap scan output dictionary
            
        Returns:
            dict: Processed and structured scan results
        """
        processed_results = {
            'timestamp': datetime.now().isoformat(),
            'hosts': []
        }
        
        try:
            # Iterate through each host in scan results
            for host_ip, host_data in scan_results['scan'].items():
                # Skip hosts that are not up
                if 'status' not in host_data or host_data['status']['state'] != 'up':
                    continue
                    
                logger.debug(f"Processing host: {host_ip}")
                
                # Extract basic host information
                host_info = {
                    'ip': host_ip,
                    'hostname': host_data.get('hostnames', [{'name': ''}])[0].get('name', ''),
                    'state': host_data.get('status', {}).get('state', ''),
                    'mac_address': host_data.get('addresses', {}).get('mac', 'N/A'),
                    'vendor': host_data.get('vendor', {}).get(host_data.get('addresses', {}).get('mac', ''), 'N/A'),
                    'ports': [],
                    'vulnerabilities': []
                }
                
                # Process TCP port scan results
                if 'tcp' in host_data:
                    for port, port_info in host_data['tcp'].items():
                        port_data = self._extract_port_data(port, port_info)
                        
                        # Process vulnerability script outputs
                        if 'script' in port_info:
                            scripts = port_info['script']
                            for script_name, output in scripts.items():
                                if 'vulners' in script_name or 'vuln' in script_name:
                                    self._process_vuln_script(host_info, port_data, output)
                        
                        host_info['ports'].append(port_data)
                
                # Process UDP port scan results if available
                if 'udp' in host_data:
                    for port, port_info in host_data['udp'].items():
                        port_data = self._extract_port_data(port, port_info)
                        host_info['ports'].append(port_data)
                
                processed_results['hosts'].append(host_info)
                
        except Exception as e:
            logger.error(f"Error processing scan results: {str(e)}")
            
        return processed_results
    
    def _extract_port_data(self, port, port_info: dict) -> dict:
        """
        Extract port information from Nmap scan data.
        
        Args:
            port: Port number
            port_info: Port scan information dictionary
            
        Returns:
            dict: Structured port data
        """
        return {
            'port': port,
            'state': port_info.get('state', ''),
            'service': port_info.get('name', ''),
            'version': port_info.get('version', ''),
            'product': port_info.get('product', ''),
            'extrainfo': port_info.get('extrainfo', '')
        }
    
    def _process_vuln_script(self, host_info: dict, port_data: dict, script_output: str):
        """
        Process Nmap vulnerability script output and extract CVE information.
        
        Args:
            host_info: Dictionary containing host information
            port_data: Dictionary containing port information
            script_output: Raw vulnerability script output string
        """
        try:
            # Track unique CVEs to prevent duplicates
            existing_cves = {vuln['cve_id'] for vuln in host_info.get('vulnerabilities', [])}
            
            # Extract CVE IDs and CVSS scores using regex pattern matching
            cve_pattern = r'(CVE-\d{4}-\d+)\s+(\d+\.\d+)'
            matches = re.findall(cve_pattern, script_output)
            
            for cve_id, cvss_score in matches:
                if cve_id not in existing_cves:
                    # Extract vulnerability summary from script output
                    summary_pattern = rf"{cve_id}.*?(?=CVE-|$)"
                    summary_match = re.search(summary_pattern, script_output, re.DOTALL)
                    summary = summary_match.group(0).strip() if summary_match else "No summary available"
                    
                    # Calculate severity based on CVSS score
                    cvss = float(cvss_score)
                    severity = 'high' if cvss >= 7.0 else 'medium' if cvss >= 4.0 else 'low'
                    
                    # Create vulnerability entry
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
        """
        Enrich scan results with vulnerability data from Shodan API.
        
        Args:
            host_info: Dictionary containing host information to enrich
        """
        try:
            # Track existing CVEs to prevent duplicates
            existing_cves = {vuln['cve_id'] for vuln in host_info.get('vulnerabilities', [])}
            
            # Query Shodan API for host information
            response = requests.get(
                f"https://api.shodan.io/shodan/host/{host_info['ip']}?key={self.shodan_api_key}",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if 'vulns' in data:
                    logger.info(f"Found Shodan vulnerabilities for {host_info['ip']}")
                    # Process each vulnerability from Shodan
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
        """
        Generate an HTML report from scan results.
        
        Args:
            results: Dictionary containing processed scan results
            output_file: Path to save the HTML report
        """
        try:
            logger.info(f"Generating report to {output_file}")
            # Generate HTML report content with styling
            html_content = self._generate_html_header(results['timestamp'])
            
            # Add section for each host
            for host in results['hosts']:
                html_content += self._generate_host_section(host)

            html_content += """
            </body>
            </html>
            """
            
            # Ensure output directory exists
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write report to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            logger.info(f"Report generated successfully at {output_file}")
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            raise

    def _generate_html_header(self, timestamp: str) -> str:
        """
        Generate HTML header with styling for the report.
        
        Args:
            timestamp: Scan timestamp to include in report
            
        Returns:
            str: HTML header content with CSS styling
        """
        return f"""
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
            <div class="timestamp">Scan performed at: {timestamp}</div>
        """

    def _generate_host_section(self, host: dict) -> str:
        """
        Generate HTML section for a single host's scan results.
        
        Args:
            host: Dictionary containing host scan information
            
        Returns:
            str: HTML content for host section
        """
        # Generate basic host information section
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
        
        # Add port information table rows
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
        
        # Add vulnerability information if present
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
    """
    Main entry point for the vulnerability scanner.
    Reads configuration from environment variables and runs the scan.
    """
    try:
        # Get scan configuration from environment variables
        target = os.getenv("NMAP_TARGET", "192.168.1.0/24")
        ports = os.getenv("NMAP_PORTS", "1-65535")
        arguments = os.getenv("NMAP_ARGS", "-sV -sC --script=vuln")
        output_file = os.getenv("NMAP_REPORT", "../Scans/nmap_report.html")
        
        logger.info("Starting vulnerability scan")
        # Initialize and run the vulnerability scanner
        scanner = VulnerabilityScanner()
        results = scanner.scan_network(target, ports, arguments)
        
        # Generate HTML report from scan results
        scanner.generate_html_report(results, output_file)
        
        logger.info("Scan and report completed successfully")
        
    except Exception as e:
        logger.error(f"Fatal error in main: {e}")
        raise

if __name__ == "__main__":
    main()
