import requests
from bs4 import BeautifulSoup
import random

def fetch_wordpress_plugins():
    url = 'https://plugins.svn.wordpress.org/'
    
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
        'Referer': 'https://wordpress.org/plugins/',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        plugins = []
        for link in soup.find_all('a'):
            plugin_name = link.get('href', '').strip('/')
            
            # Filter out non-plugin links (like parent directory)
            if plugin_name and not plugin_name.startswith('.'):
                plugins.append(f'wp-content/plugins/{plugin_name}/')
        
        # Write plugins to file
        with open('./data/wp-plugins.fuzz.txt', 'w') as f:
            for plugin in sorted(plugins):
                f.write(f"{plugin}\n")
        
        print(f"Successfully wrote {len(plugins)} plugins to ./data/wp-plugins.fuzz.txt")
    
    except requests.RequestException as e:
        print(f"Error fetching plugins: {e}")

if __name__ == "__main__":
    fetch_wordpress_plugins()