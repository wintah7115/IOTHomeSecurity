import nmap
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

class NmapScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        
    def scan_network(self, target: str, ports: str = "1-1024", arguments: str = "-sV -sS") -> Dict:
        """
        Perform a network scan using Nmap.
        
        Args:
            target: IP address or network range (e.g., "192.168.1.0/24")
            ports: Port range to scan (e.g., "22-443" or "80,443,8080")
            arguments: Additional Nmap arguments
            
        Returns:
            Dictionary containing scan results
        """
        try:
            scan_results = self.scanner.scan(hosts=target, ports=ports, arguments=arguments)
            return self._process_results(scan_results)
        except Exception as e:
            print(f"Error during scan: {str(e)}")
            return {}
            
    def _process_results(self, scan_results: Dict) -> Dict:
        """Process and format the Nmap scan results."""
        processed_results = {
            'timestamp': datetime.now(),
            'hosts': []
        }
        
        for host in scan_results['scan'].values():
            if 'status' not in host or host['status']['state'] != 'up':
                continue
                
            host_info = {
                'ip': host.get('addresses', {}).get('ipv4', ''),
                'hostname': host.get('hostnames', [{'name': ''}])[0].get('name', ''),
                'state': host.get('status', {}).get('state', ''),
                'ports': []
            }
            
            if 'tcp' in host:
                for port, port_info in host['tcp'].items():
                    port_data = {
                        'port': port,
                        'state': port_info.get('state', ''),
                        'service': port_info.get('name', ''),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', '')
                    }
                    host_info['ports'].append(port_data)
            
            processed_results['hosts'].append(host_info)
 #           print(processed_results['timestamp'])
        return processed_results
        
    def generate_html_report(self, results: Dict, output_file: str) -> None:
        """Generate an HTML report from the scan results."""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .host-section {{ margin-bottom: 30px; }}
                .timestamp {{ color: #666; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <h1>Network Scan Report</h1>
            <div class="timestamp">Scan performed at: {results['timestamp']}</div>
        """
        
        for host in results['hosts']:
            html_content += f"""
            <div class="host-section">
                <h2>Host: {host['ip']}</h2>
                <p>Hostname: {host['hostname']}</p>
                <p>State: {host['state']}</p>
                
                <h3>Open Ports:</h3>
                <table>
                    <tr>
                        <th>Port</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Product</th>
                    </tr>
            """
            
            for port in host['ports']:
                html_content += f"""
                    <tr>
                        <td>{port['port']}</td>
                        <td>{port['state']}</td>
                        <td>{port['service']}</td>
                        <td>{port['version']}</td>
                        <td>{port['product']}</td>
                    </tr>
                """
                
            html_content += """
                </table>
            </div>
            """
            
        html_content += """
        </body>
        </html>
        """
        
        with open(f"../Scans/{output_file}", 'w', encoding='utf-8') as f:
            f.write(html_content)

def main():
    # Get configuration from environment variables
    target = os.getenv("NMAP_TARGET", "192.168.1.0/24")
    ports = os.getenv("NMAP_PORTS", "1-1024")
    arguments = os.getenv("NMAP_ARGS", "-sV -sS")
    output_file = os.getenv("NMAP_REPORT", "nmap_report.html")
    
    scanner = NmapScanner()
    results = scanner.scan_network(target, ports, arguments)
    scanner.generate_html_report(results, output_file)
    
if __name__ == "__main__":
    main()
