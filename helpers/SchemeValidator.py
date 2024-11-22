from typing import Optional
import requests
from urllib.parse import urlparse
from functools import lru_cache
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl

class SchemeValidator:
    def __init__(self, timeout: int = 5, max_retries: int = 2):
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create and configure a requests session for reuse"""
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            max_retries=self.max_retries,
            pool_connections=10,
            pool_maxsize=10
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    @lru_cache(maxsize=1024)
    def _check_ssl_support(self, hostname: str) -> bool:
        """Check if domain supports SSL without making HTTP request"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.version() is not None
        except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError):
            return False

    def _validate_scheme(self, url: str, scheme: str) -> Optional[bool]:
        """Validate if a given scheme works for the domain"""
        try:
            response = self.session.head(
                f"{scheme}://{urlparse(url).netloc}",
                timeout=self.timeout,
                allow_redirects=True
            )
            return response.status_code < 400
        except requests.RequestException:
            return None

    def _ensure_scheme(self, domain: str) -> str:
        """
        Ensure domain has the correct scheme (http:// or https://)
        
        Args:
            domain: Domain name with or without scheme
            
        Returns:
            Domain with correct scheme
            
        Raises:
            ValueError: If domain is invalid
            ConnectionError: If neither HTTP nor HTTPS work
        """
        # Input validation
        if not domain or not isinstance(domain, str):
            raise ValueError("Invalid domain")

        # Clean and parse domain
        domain = domain.strip().lower()
        parsed = urlparse(domain)
        hostname = parsed.netloc or parsed.path
        
        if not hostname:
            raise ValueError("Invalid domain format")

        # Return as-is if scheme is already present and working
        if parsed.scheme:
            if self._validate_scheme(domain, parsed.scheme):
                return domain

        # Check SSL support first (faster than making HTTP requests)
        if self._check_ssl_support(hostname):
            return f"https://{hostname}"

        # Try both schemes concurrently
        schemes = ['https', 'http']
        working_scheme = None
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_to_scheme = {
                executor.submit(self._validate_scheme, hostname, scheme): scheme
                for scheme in schemes
            }
            
            for future in as_completed(future_to_scheme):
                scheme = future_to_scheme[future]
                try:
                    result = future.result()
                    if result:
                        working_scheme = scheme
                        # Cancel remaining futures
                        for f in future_to_scheme:
                            f.cancel()
                        break
                except Exception:
                    continue

        if working_scheme:
            return f"{working_scheme}://{hostname}"
            
        # If no scheme works, default to HTTPS (secure by default)
        return f"https://{hostname}"

    def __call__(self, domain: str) -> str:
        """Make the class callable for easier use"""
        return self._ensure_scheme(domain)