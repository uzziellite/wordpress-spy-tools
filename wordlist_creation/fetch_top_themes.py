#!/usr/bin/env python3

import requests
import argparse
import os
import json
import math
from typing import List, Dict
from time import sleep

class WPThemeFetcher:
    """
    Class to handle WordPress theme fetching with pagination
    """
    def __init__(self):
        self.base_url = "https://api.wordpress.org/themes/info/1.1/"
        self.per_page = 250  # WordPress API maximum limit per page

    def fetch_page(self, page: int, per_page: int) -> Dict:
        """
        Fetch a single page of themes
        """
        params = {
            "action": "query_themes",
            "request[browse]": "popular",
            "request[page]": page,
            "request[per_page]": per_page,
            "request[fields][description]": True,
            "request[fields][sections]": False,
            "request[fields][rating]": True,
            "request[fields][downloaded]": True,
            "request[fields][downloadlink]": True,
            "request[fields][last_updated]": True,
            "request[fields][homepage]": True,
            "request[fields][tags]": True,
            "request[fields][template]": True,
            "request[fields][versions]": True,
            "request[fields][screenshot_url]": True
        }
        
        try:
            response = requests.get(self.base_url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching page {page}: {e}")
            return {}

    def get_top_themes(self, limit: int, progress_callback=None) -> List[Dict]:
        """
        Fetch top themes using pagination to get exact number requested
        """
        themes = []
        total_pages = math.ceil(limit / self.per_page)
        remaining = limit

        for page in range(1, total_pages + 1):
            # Calculate how many themes to fetch in this page
            current_page_limit = min(self.per_page, remaining)
            
            if progress_callback:
                progress_callback(page, total_pages)

            # Fetch page data
            response_data = self.fetch_page(page, current_page_limit)
            
            if not response_data or 'themes' not in response_data:
                print(f"Warning: Failed to fetch page {page}")
                continue

            # Add themes from this page
            page_themes = response_data['themes']
            themes.extend(page_themes)
            
            # Update remaining count
            remaining -= len(page_themes)
            
            # Add small delay to be nice to the API
            sleep(0.5)
            
            # Break if we've got enough themes
            if len(themes) >= limit:
                break

        # Trim to exact number requested
        return themes[:limit]

def setup_argument_parser() -> argparse.ArgumentParser:
    """
    Set up command line argument parser
    """
    parser = argparse.ArgumentParser(
        description='Generate WordPress theme paths for top [n] themes with pagination support'
    )
    parser.add_argument(
        '-n', '--number',
        type=int,
        required=True,
        help='Number of top themes to fetch'
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
        help='Also save detailed theme information as JSON'
    )
    return parser

def save_theme_paths(themes: List[Dict], output_path: str) -> None:
    """
    Save theme paths to a file
    """
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for theme in themes:
                theme_path = f"wp-content/themes/{theme['slug']}"
                f.write(f"{theme_path}\n")
        
        print(f"\nSuccessfully saved {len(themes)} theme paths to {output_path}")
    except IOError as e:
        print(f"\nError saving to file: {e}")

def save_json_data(themes: List[Dict], output_path: str) -> None:
    """
    Save detailed theme information as JSON
    """
    json_path = os.path.splitext(output_path)[0] + '.json'
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(themes, f, indent=2)
        print(f"Successfully saved detailed theme information to {json_path}")
    except IOError as e:
        print(f"Error saving JSON data: {e}")

def show_progress(current_page: int, total_pages: int):
    """
    Display progress bar
    """
    progress = (current_page / total_pages) * 100
    print(f"\rFetching themes: Page {current_page}/{total_pages} ({progress:.1f}%)", end='')

def main():
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Validate number of themes
    if args.number <= 0:
        print("Error: Number of themes must be greater than 0")
        return

    print(f"Preparing to fetch {args.number} themes...")
    
    # Initialize fetcher and get themes
    fetcher = WPThemeFetcher()
    themes = fetcher.get_top_themes(args.number, progress_callback=show_progress)

    if not themes:
        print("\nNo themes were fetched. Please check your internet connection and try again.")
        return

    # Save theme paths
    save_theme_paths(themes, args.output)

    # Save JSON data if requested
    if args.json:
        save_json_data(themes, args.output)

    # Print summary
    print(f"Total themes fetched: {len(themes)}")

if __name__ == "__main__":
    main()