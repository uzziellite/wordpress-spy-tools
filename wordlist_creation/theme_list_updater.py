import requests
from bs4 import BeautifulSoup
import random

def fetch_wordpress_themes():
    url = 'https://themes.svn.wordpress.org/'
    
    # List of realistic user agent strings
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
    ]
    
    headers = {
        'User-Agent': random.choice(user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://wordpress.org/themes/',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        themes = []
        for link in soup.find_all('a'):
            theme_name = link.get('href', '').strip('/')
            
            # Filter out non-theme links (like parent directory)
            if theme_name and not theme_name.startswith('.'):
                themes.append(f'wp-content/themes/{theme_name}/')
        
        # Write themes to file
        with open('./data/wp-themes.fuzz.txt', 'w') as f:
            for plugin in sorted(themes):
                f.write(f"{plugin}\n")
        
        print(f"Successfully wrote {len(themes)} themes to ./data/wp-themes.fuzz.txt")
    
    except requests.RequestException as e:
        print(f"Error fetching themes: {e}")

if __name__ == "__main__":
    fetch_wordpress_themes()