import dns.resolver
import socket
import ssl
import requests
import urllib3
from tabulate import tabulate
import warnings
import whois
from datetime import datetime
import nmap
import sys
import logging
import random
import textwrap

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s: %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class AdvancedDomainSecurityAnalyzer:
    def __init__(self, domain, start_port=1, end_port=1000, verbose=True):
        """
        Initialize the security analyzer with domain and port range
        
        :param domain: Domain to analyze
        :param start_port: Starting port of the scan range (default 1)
        :param end_port: Ending port of the scan range (default 1000)
        :param verbose: Enable detailed logging
        """
        try:
            # Initial startup logging
            logger.info(f"🔍 Initializing Domain Security Analysis")
            logger.info(f"Domain: {domain}")
            
            # Resolve IP
            logger.info(f"🌐 Resolving domain IP...")
            self.domain = domain
            self.ip_address = socket.gethostbyname(domain)
            print("\n")
            logger.info(f"✅ Domain IP resolved: {self.ip_address}")
            print("\n")
            
            self.start_port = start_port
            self.end_port = end_port
            self.verbose = verbose
            self.vulnerabilities = []
            
            # Suppress warnings
            warnings.filterwarnings('ignore', message='Unverified HTTPS request')
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
        except socket.gaierror:
            logger.error(f"❌ Could not resolve domain {domain}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"❌ Initialization error: {e}")
            sys.exit(1)

    def advanced_port_scan(self):
        """
        Perform advanced port scanning with optimized performance
        """
        logger.info(f"\n🔬 Initiating Optimized Port Scan on {self.ip_address}")
        logger.info(f"   Scanning port range: {self.start_port} - {self.end_port}")
        
        try:
            nm = nmap.PortScanner()
            
            # Fix: Use comma-separated port range
            port_arg = f'{self.start_port}-{self.end_port}'
            
            # Optimized scan arguments
            scan_args = f'-sS -sV -n -Pn -p{port_arg} -T4 --max-retries 2 --max-scan-delay 20'
            
            logger.info("🚀 Launching optimized Nmap scan. Please be patient...")
            
            # Perform the scan
            nm.scan(hosts=self.ip_address, arguments=scan_args)
            
            # Collect port results
            port_results = []
                
            # Iterate through hosts and protocols
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    
                    for port in ports:
                        service = nm[host][proto][port]
                        
                        # Only record open ports
                        if service['state'] == 'open':
                            port_result = {
                                'Port': port,
                                'State': service['state'],
                                'Service': service.get('name', 'Unknown'),
                                'Product': service.get('product', 'N/A'),
                                'Version': service.get('version', 'N/A'),
                            }

                            port_results.append(port_result)
                        
                        # Update progress bar
            
            return port_results
        
        except Exception as e:
            logger.error(f"❌ Unexpected error during port scan: {e}")
            return [{'Error': str(e)}]

    def get_dns_records(self):
        """
        Retrieve various DNS records for the domain
        """
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        dns_records = []

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                for rdata in answers:
                    dns_records.append({
                        'Type': record_type,
                        'Value': str(rdata)
                    })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue

        return dns_records
    
    def check_cors_configuration(self, headers):
        """
        Check CORS (Cross-Origin Resource Sharing) configuration
        """
        cors_header = headers.get('Access-Control-Allow-Origin', '')
        if cors_header == '*':
            return {
                'Header': 'CORS Configuration',
                'Value': cors_header,
                'Status': 'Vulnerable',
                'Severity': 'High',
                'Description': 'Wildcard CORS configuration allows requests from any origin',
                'Recommendation': 'Use specific, restricted origin values'
            }
        
        return {
            'Header': 'CORS Configuration',
            'Value': cors_header or 'Not Set',
            'Status': 'Secure' if cors_header else 'Missing',
            'Severity': 'Low',
            'Description': 'CORS configuration review',
            'Recommendation': 'Implement strict CORS policy'
        }

    def check_cookie_security(self, headers):
        """
        Check cookie security attributes
        """
        set_cookie = headers.get('Set-Cookie', '')
        checks = {
            'HttpOnly': 'Prevents client-side script access to cookies',
            'Secure': 'Ensures cookies are only sent over HTTPS',
            'SameSite': 'Provides protection against CSRF attacks'
        }
        
        missing_attributes = [attr for attr in checks if attr not in set_cookie]
        
        if missing_attributes:
            return {
                'Header': 'Cookie Security',
                'Value': set_cookie,
                'Status': 'Vulnerable',
                'Severity': 'High',
                'Description': f'{", ".join(missing_attributes)} missing',
                'Recommendation': 'Add HttpOnly, Secure, and SameSite attributes to cookies'
            }
        
        return {
            'Header': 'Cookie Security',
            'Value': set_cookie,
            'Status': 'Secure',
            'Severity': 'Low',
            'Description': 'Cookies have appropriate security attributes',
            'Recommendation': 'Maintain current cookie configuration'
        }

    def analyze_headers(self):
        """
        Analyze website headers for security vulnerabilities
        """
        try:
            # Prepare URL
            url = f"https://{self.domain}"

            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
            ]
            
            spoofed_header = {
                'User-Agent': random.choice(user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Referer': url,
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # Disable SSL verification warnings (use cautiously)
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Send request with minimal timeout
            response = requests.get(url, timeout=30, verify=False, headers=spoofed_header)
            
            # Collect headers
            headers = response.headers
            header_analysis = []

            # Security header checks
            security_checks = {
                'X-XSS-Protection': {
                    'recommended': '1; mode=block',
                    'description': 'XSS protection header'
                },
                'X-Frame-Options': {
                    'recommended': ['DENY', 'SAMEORIGIN'],
                    'description': 'Prevents clickjacking attacks'
                },
                'Strict-Transport-Security': {
                    'recommended': 'max-age=31536000; includeSubDomains',
                    'description': 'HSTS prevents protocol downgrade attacks'
                },
                'X-Content-Type-Options': {
                    'recommended': 'nosniff',
                    'description': 'Prevents MIME type sniffing'
                },
                'Content-Security-Policy': {
                    'recommended': 'default-src \'self\'',
                    'description': 'Prevents XSS and data injection'
                }
            }

            # Check each security header
            for header, details in security_checks.items():
                status = 'Missing'
                recommendation = details['recommended']
                
                if header in headers:
                    value = headers[header]
                    if isinstance(details['recommended'], list):
                        status = 'Secure' if any(rec in value for rec in details['recommended']) else 'Vulnerable'
                    else:
                        status = 'Secure' if details['recommended'] in value else 'Vulnerable'
                
                header_analysis.append({
                    'Header': header,
                    'Value': headers.get(header, 'N/A'),
                    'Status': status,
                    'Recommendation': recommendation,
                    'Description': details['description']
                })

                additional_checks = [
                    self.check_cors_configuration(headers),
                    self.check_cookie_security(headers)
                ]
                
                header_analysis.extend(additional_checks)

            # Server and technology detection
            server_info = {
                'Server': headers.get('Server', 'Not Disclosed'),
                'X-Powered-By': headers.get('X-Powered-By', 'Not Disclosed'),
                'Technology': response.headers.get('X-Powered-By', 'Unknown')
            }

            return header_analysis, server_info

        except requests.exceptions.RequestException as e:
            return [], {'Error': str(e)}

    def whois_lookup(self):
        """
        Perform WHOIS lookup to get domain registration details
        """
        try:
            domain_info = whois.whois(self.domain)
            return {
                'Registrar': domain_info.registrar,
                'Creation Date': domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date,
                'Expiration Date': domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date
            }
        except Exception as e:
            return {'Error': str(e)}

    def ssl_check(self):
        """
        Check SSL certificate details
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as secure_sock:
                    cert = secure_sock.getpeercert()
                    
                    return {
                        'Subject': dict(x[0] for x in cert['subject']),
                        'Issuer': dict(x[0] for x in cert['issuer']),
                        'Version': cert.get('version', 'N/A'),
                        'Expiration': datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    }
        except Exception as e:
            return {'Error': str(e)}

    def run_analysis(self):
        """
        Comprehensive domain security analysis
        """
        print(f"Security Analysis for {self.domain}\n")
        
        # DNS Records
        print("DNS Records:")
        dns_records = self.get_dns_records()
        for row in dns_records:
            for key in row:
                row[key] = "\n".join(textwrap.wrap(str(row[key]), width=40))
        print(tabulate(dns_records, headers='keys', tablefmt='grid'))
        print("\n")
        
        # Header Analysis
        header_analysis, server_info = self.analyze_headers()

        # Wrap header analysis text
        for row in header_analysis:
            for key in row:
                row[key] = "\n".join(textwrap.wrap(str(row[key]), width=20))
        
        print("Security Headers Analysis:")
        print(tabulate(header_analysis, headers='keys', tablefmt='grid'))
        print("\n")
        
        print("Server Information:")
        for key, value in server_info.items():
            print(f"{key}: {value}")
        print("\n")
        
        # WHOIS Lookup
        whois_info = self.whois_lookup()
        print("Domain Registration Details:")
        for key, value in whois_info.items():
            print(f"{key}: {value}")
        print("\n")
        
        # SSL Certificate Check
        ssl_details = self.ssl_check()
        print("SSL Certificate Details:")
        for key, value in ssl_details.items():
            print(f"{key}: {value}")
        print("\n")

        # Port Scanning
        port_results = self.advanced_port_scan()
        print("\n")
        print("Open Ports and Services:")
        print(tabulate(port_results, headers='keys', tablefmt='grid'))
        print("\n")

def main():
    try:
        # Welcome message
        print("🕵️ Advanced Domain Security Analyzer 🌐")
        print("======================================")
        
        # Get domain
        domain = input("Enter domain to analyze (e.g., example.com): ").strip()
        
        # Get optional port range
        while True:
            try:
                port_range = input("Enter port range (start-end, press Enter for default 1-1000): ").strip()
                
                if not port_range:
                    # Default range
                    analyzer = AdvancedDomainSecurityAnalyzer(domain)
                    break
                
                # Parse user-defined port range
                start, end = map(int, port_range.split('-'))
                
                if start < 1 or end > 65535 or start > end:
                    print("❌ Invalid port range. Ports must be between 1-65535, and start port must be less than end port.")
                    continue
                
                analyzer = AdvancedDomainSecurityAnalyzer(domain, start, end)
                break
            
            except ValueError:
                print("❌ Invalid input. Please enter ports as 'start-end' (e.g., '1-1000').")
        
        # Run analysis
        analyzer.run_analysis()
    
    except KeyboardInterrupt:
        print("\n⏹️ Program interrupted. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()