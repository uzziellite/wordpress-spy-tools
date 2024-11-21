import os
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
import time
from pathlib import Path
import logging
import concurrent.futures
from urllib.parse import urljoin
import argparse
from tqdm import tqdm
import json
import csv
from requests.adapters import HTTPAdapter
from requests.adapters import Retry
import yaml
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text
import re
import signal
import threading

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

console = Console()
executor = None  # Global executor reference for cleanup
progress_bar = None  # Global progress bar reference
exit_event = threading.Event()

def cleanup():
    """Clean up resources before exit"""
    if progress_bar:
        progress_bar.close()
    if executor:
        executor._threads.clear()
        concurrent.futures.thread._threads_queues.clear()
    console.print("\n[grey]script terminated[/grey]")

def signal_handler(signum, frame):
    """Handle interrupt signals gracefully"""
    exit_event.set()
    cleanup()
    # Use os._exit. This is to avoid threading cleanup issues
    os._exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

class URLChecker:
    def __init__(self, base_url, timeout=10, max_retries=3, headers=None, verify_ssl=True):
        self.base_url = base_url
        self.timeout = timeout
        self.headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.verify_ssl = verify_ssl
        
        # Setup session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def check_url(self, url_data):
        """
        Check a single URL and return its status
        url_data is a tuple of (base_url, path)
        """
        base_url, path = url_data
        full_url = urljoin(base_url, path.strip())
        start_time = time.time()
        
        try:
            response = self.session.get(
                full_url,
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response_time = time.time() - start_time
            status_code = response.status_code
            
            result = {
                'url': full_url,
                'status_code': status_code,
                'response_time': round(response_time, 3),
                'error': None,
                'redirect_url': response.url if response.history else None
            }
            
            return result
            
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            logging.error(f"{full_url} - {error_msg}")
            return {
                'url': full_url,
                'status_code': None,
                'response_time': time.time() - start_time,
                'error': error_msg,
                'redirect_url': None
            }

def setup_logging(log_file='url_checker.log'):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

def print_banner():
    console.print("""
    [green]
    Developed by: Uzziel Lite
    WordPress Plugins Fuzzing v1.0
    [/green]
    """)

def export_results(results, output_format, filename):
    """Export results in the specified format"""
    if output_format == 'json':
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
    
    elif output_format == 'csv':
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['url', 'status_code', 'response_time', 'error', 'redirect_url'])
            writer.writeheader()
            writer.writerows(results)
    
    elif output_format == 'yaml':
        with open(filename, 'w') as f:
            yaml.dump(results, f)

def extract_plugin_name(url):
    """Extract plugin name from WordPress plugin URL"""
    match = re.search(r'/wp-content/plugins/([^/]+)', url)
    return match.group(1) if match else url

def display_results_table(results):
    """Display results in a formatted table, filtering out 404 status code"""
    table = Table(title="Plugins Discovered", box=box.ROUNDED)
    
    table.add_column("Plugin Name", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Response Time", justify="right")
    table.add_column("Redirect URL", style="magenta")
    
    for result in results:
        status_code = result['status_code']
        if status_code == 404:
            continue
            
        status_style = {
            200: "green",
            301: "yellow",
            302: "yellow",
            403: "red",
            None: "red"
        }.get(status_code, "white")
        
        plugin_name = extract_plugin_name(result['url'])
        
        status = str(status_code) if status_code else f"Error: {result['error']}"
        table.add_row(
            plugin_name,
            Text(status, style=status_style),
            f"{result['response_time']:.3f}s",
            result['redirect_url'] or ""
        )
    
    console.print(table)

def process_urls(checker, file_path, max_workers=10):
    """Process URLs concurrently using a ThreadPoolExecutor with a growing results table"""
    global executor, progress_bar
    results = []
    
    # Create a single table to be updated
    table = Table(title="Plugins Discovered", box=box.ROUNDED)
    table.add_column("Plugin Name", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Response Time", justify="right")
    table.add_column("Redirect URL", style="magenta")
    
    try:
        with open(file_path, 'r') as file:
            paths = [line.strip() for line in file if line.strip()]
        
        url_data = [(checker.base_url, path) for path in paths]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            executor = ex
            futures = {ex.submit(checker.check_url, data): data for data in url_data}
            
            with tqdm(total=len(futures), desc="Searching Plugins: ", unit="url") as pbar:
                progress_bar = pbar
                
                for future in concurrent.futures.as_completed(futures):
                    if exit_event.is_set():
                        break
                    
                    try:
                        result = future.result()
                        if result is not None and result['status_code'] != 404:
                            # Determine status style
                            status_style = {
                                200: "green",
                                301: "yellow",
                                302: "yellow",
                                403: "red",
                                None: "red"
                            }.get(result['status_code'], "white")
                            
                            # Prepare status text
                            status = str(result['status_code']) if result['status_code'] else f"Error: {result['error']}"
                            
                            # Extract plugin name
                            plugin_name = extract_plugin_name(result['url'])
                            
                            # Add row to the table
                            table.add_row(
                                plugin_name,
                                Text(status, style=status_style),
                                f"{result['response_time']:.3f}s",
                                result['redirect_url'] or ""
                            )
                            
                            # Clear console and reprint the entire updated table
                            console.clear()
                            console.print(table)
                            
                            results.append(result)
                        pbar.update(1)
                    except Exception as e:
                        logging.error(f"Error processing URL: {str(e)}")
                        pbar.update(1)
                        continue
    
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    
    return results

def main():
    parser = argparse.ArgumentParser(description='Concurrent URL Status Checker')
    parser.add_argument('base_url', help='Base URL to prepend to paths')
    parser.add_argument('file_path', help='Path to file containing URL paths')
    parser.add_argument('-w', '--workers', type=int, default=10, 
                        help='Number of concurrent workers (default: 10)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('-r', '--retries', type=int, default=3,
                        help='Maximum number of retries for failed requests (default: 3)')
    parser.add_argument('--no-verify-ssl', action='store_true',
                        help='Disable SSL certificate verification')
    parser.add_argument('--headers', type=json.loads, default=None,
                        help='Additional headers as JSON string')
    parser.add_argument('--export', choices=['json', 'csv', 'yaml'],
                        help='Export results in specified format')
    parser.add_argument('--output', help='Output file name for export')
    parser.add_argument('--log-file', default='url_checker.log',
                        help='Log file path (default: url_checker.log)')
    
    try:
        args = parser.parse_args()
        
        print_banner()
        setup_logging(args.log_file)
        
        file_path = Path(args.file_path)
        if not file_path.exists():
            console.print(f"[red]Error: File {file_path} does not exist![/red]")
            sys.exit(1)
        
        start_time = time.time()
        
        console.print(f"\nStarting Plugin Search with base URL: [cyan]{args.base_url}[/cyan]\n")
        
        checker = URLChecker(
            args.base_url,
            timeout=args.timeout,
            max_retries=args.retries,
            headers=args.headers,
            verify_ssl=not args.no_verify_ssl
        )
        
        results = process_urls(checker, file_path, args.workers)
        
        if not exit_event.is_set():
            display_results_table(results)
            
            if args.export and args.output:
                export_results(results, args.export, args.output)
                console.print(f"\n[green]Results exported to: {args.output}[/green]")
            
            stats = {
                'total': len(results),
                'success': len([r for r in results if r['status_code'] is not None 
                    and r['status_code'] != 404]),
                'total_time': time.time() - start_time
            }
            
            console.print("\n[bold]Summary:[/bold]")
            console.print(f"Total URLs: {stats['total']}")
            console.print(f"Discovered: [green]{stats['success']}[/green]")
            console.print(f"Total time: [blue]{stats['total_time']:.2f}[/blue] seconds")
    
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)

if __name__ == "__main__":
    main()