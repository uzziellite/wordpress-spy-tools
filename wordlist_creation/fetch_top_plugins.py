#!/usr/bin/env python3

import requests
import argparse
import os
import json
import math
from typing import List, Dict
from time import sleep

class WPPluginFetcher:
    """
    Class to handle WordPress plugin fetching with pagination
    """
    def __init__(self):
        self.base_url = "https://api.wordpress.org/plugins/info/1.2/"
        self.per_page = 250  # WordPress API maximum limit per page

    def fetch_page(self, page: int, per_page: int) -> Dict:
        """
        Fetch a single page of plugins
        """
        params = {
            "action": "query_plugins",
            "request[browse]": "popular",
            "request[page]": page,
            "request[per_page]": per_page
        }
        
        try:
            response = requests.get(self.base_url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching page {page}: {e}")
            return {}

    def get_top_plugins(self, limit: int, progress_callback=None) -> List[Dict]:
        """
        Fetch top plugins using pagination to get exact number requested
        """
        plugins = []
        total_pages = math.ceil(limit / self.per_page)
        remaining = limit

        for page in range(1, total_pages + 1):
            # Calculate how many plugins to fetch in this page
            current_page_limit = min(self.per_page, remaining)
            
            if progress_callback:
                progress_callback(page, total_pages)

            # Fetch page data
            response_data = self.fetch_page(page, current_page_limit)
            
            if not response_data or 'plugins' not in response_data:
                print(f"Warning: Failed to fetch page {page}")
                continue

            # Add plugins from this page
            page_plugins = response_data['plugins']
            plugins.extend(page_plugins)
            
            # Update remaining count
            remaining -= len(page_plugins)
            
            # Add small delay to be nice to the API
            sleep(0.5)
            
            # Break if we've got enough plugins
            if len(plugins) >= limit:
                break

        # Trim to exact number requested
        return plugins[:limit]

def setup_argument_parser() -> argparse.ArgumentParser:
    """
    Set up command line argument parser
    """
    parser = argparse.ArgumentParser(
        description='Generate WordPress plugin paths for top [n] plugins with pagination support'
    )
    parser.add_argument(
        '-n', '--number',
        type=int,
        required=True,
        help='Number of top plugins to fetch'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        required=True,
        help='Output file path (e.g., /path/to/output.txt)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Also save detailed plugin information as JSON'
    )
    return parser

def save_plugin_paths(plugins: List[Dict], output_path: str) -> None:
    """
    Save plugin paths to a file
    """
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for plugin in plugins:
                plugin_path = f"wp-content/plugins/{plugin['slug']}"
                f.write(f"{plugin_path}\n")
        
        print(f"\nSuccessfully saved {len(plugins)} plugin paths to {output_path}")
    except IOError as e:
        print(f"\nError saving to file: {e}")

def save_json_data(plugins: List[Dict], output_path: str) -> None:
    """
    Save detailed plugin information as JSON
    """
    json_path = os.path.splitext(output_path)[0] + '.json'
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(plugins, f, indent=2)
        print(f"Successfully saved detailed plugin information to {json_path}")
    except IOError as e:
        print(f"Error saving JSON data: {e}")

def show_progress(current_page: int, total_pages: int):
    """
    Display progress bar
    """
    progress = (current_page / total_pages) * 100
    print(f"\rFetching plugins: Page {current_page}/{total_pages} ({progress:.1f}%)", end='')

def main():
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Validate number of plugins
    if args.number <= 0:
        print("Error: Number of plugins must be greater than 0")
        return

    print(f"Preparing to fetch {args.number} plugins...")
    
    # Initialize fetcher and get plugins
    fetcher = WPPluginFetcher()
    plugins = fetcher.get_top_plugins(args.number, progress_callback=show_progress)

    if not plugins:
        print("\nNo plugins were fetched. Please check your internet connection and try again.")
        return

    # Save plugin paths
    save_plugin_paths(plugins, args.output)

    # Save JSON data if requested
    if args.json:
        save_json_data(plugins, args.output)

    # Print summary
    print(f"Total plugins fetched: {len(plugins)}")

if __name__ == "__main__":
    main()