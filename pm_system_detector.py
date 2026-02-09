#!/usr/bin/env python3
"""
Property Management System Detector (Portal Detection Only)

Identifies property management software platforms (AppFolio, Yardi, Buildium,
RentManager, Entrata, PropertyWare, RentVine) for property management company
websites. Does NOT detect payment processors or RBP providers.

Usage:
    python pm_system_detector.py detect example.com
    python pm_system_detector.py batch input.csv output.csv
    python pm_system_detector.py batch input.csv output.csv --limit 100
    python pm_system_detector.py export output.csv
    python pm_system_detector.py stats
"""

import argparse
import csv
import json
import logging
import re
import sqlite3
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result of property management system detection."""
    domain: str
    portal_system: Optional[str] = None
    portal_subdomain: Optional[str] = None
    confidence: str = "low"
    detection_method: Optional[str] = None
    validated: bool = False
    validation_website: Optional[str] = None
    error: Optional[str] = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class RateLimiter:
    """Per-host rate limiter to avoid overwhelming individual servers."""

    def __init__(self, requests_per_second: float = 2.0):
        self.min_interval = 1.0 / requests_per_second
        self.host_times = {}
        self.lock = threading.Lock()

    def wait(self, host: str = None):
        """Wait if necessary to respect rate limit for a specific host."""
        if not host:
            return

        with self.lock:
            last_time = self.host_times.get(host, 0)
            elapsed = time.time() - last_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.host_times[host] = time.time()


class PlaywrightFetcher:
    """Lazy Playwright-based fetcher for JS-rendered and captcha-protected sites.

    Shares a single Chromium browser instance across all callers, with
    isolated BrowserContext per fetch for thread safety. Blocks images/fonts
    for speed. Gracefully degrades if Playwright is not installed.
    """

    def __init__(self, headless: bool = True):
        self._headless = headless
        self._browser = None
        self._playwright = None
        self._lock = threading.Lock()
        self._render_lock = threading.Lock()  # Serialize all Playwright page operations
        self._available = None  # None = not yet checked

    def _ensure_browser(self):
        """Lazy-start browser with double-checked locking."""
        if self._browser is not None:
            return True
        with self._lock:
            if self._browser is not None:
                return True
            if self._available is False:
                return False
            try:
                from playwright.sync_api import sync_playwright
                self._playwright = sync_playwright().start()
                self._browser = self._playwright.chromium.launch(headless=self._headless)
                self._available = True
                logger.info("Playwright browser started (Tier 5 enabled)")
                return True
            except Exception as e:
                self._available = False
                logger.warning(f"Playwright unavailable, Tier 5 disabled: {e}")
                return False

    @property
    def available(self) -> bool:
        """Check if Playwright can be used (attempts lazy init)."""
        if self._available is None:
            return self._ensure_browser()
        return self._available

    def fetch_rendered_page(self, url: str, wait_seconds: float = 3.0,
                            captcha_wait: float = 15.0) -> Optional[dict]:
        """Render a page and return HTML + DOM links.

        Returns dict with keys: 'html', 'links' (list of {href, text}),
        'final_url', or None on failure.

        Serialized via _render_lock — Playwright's sync API uses greenlets
        that break under concurrent thread access.
        """
        if not self._ensure_browser():
            return None

        with self._render_lock:
            return self._do_fetch(url, wait_seconds, captcha_wait)

    def _do_fetch(self, url: str, wait_seconds: float,
                  captcha_wait: float) -> Optional[dict]:
        """Internal: perform the actual Playwright page fetch (must be called under _render_lock)."""
        context = None
        try:
            context = self._browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                           '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                viewport={'width': 1280, 'height': 720},
                java_script_enabled=True,
            )
            # Block images and fonts for speed
            context.route("**/*.{png,jpg,jpeg,gif,svg,webp,ico,woff,woff2,ttf,eot}",
                          lambda route: route.abort())

            page = context.new_page()
            page.set_default_timeout(30000)

            try:
                page.goto(url, wait_until='domcontentloaded', timeout=30000)
            except Exception as e:
                logger.debug(f"Playwright navigation error for {url}: {e}")
                return None

            # Wait for JS rendering
            page.wait_for_timeout(int(wait_seconds * 1000))

            # Check for captcha/challenge pages and wait for them to resolve
            body_text = page.evaluate("() => document.body ? document.body.innerText : ''")
            captcha_indicators = ['just a moment', 'checking your browser',
                                  'verify you are human', 'captcha', 'challenge']
            is_captcha = any(ind in body_text.lower() for ind in captcha_indicators)

            if is_captcha:
                logger.debug(f"Captcha detected on {url}, waiting up to {captcha_wait}s")
                # Wait for captcha to resolve (JS challenges often auto-resolve)
                try:
                    page.wait_for_function(
                        """() => {
                            const text = document.body ? document.body.innerText.toLowerCase() : '';
                            return !text.includes('just a moment')
                                && !text.includes('checking your browser')
                                && !text.includes('verify you are human');
                        }""",
                        timeout=int(captcha_wait * 1000)
                    )
                    page.wait_for_timeout(2000)  # Extra settle time
                except Exception:
                    logger.debug(f"Captcha did not resolve for {url}")

            # Try to dismiss cookie consent banners
            try:
                for selector in [
                    'button:has-text("Accept")', 'button:has-text("Got it")',
                    'button:has-text("OK")', 'button:has-text("I agree")',
                    '[id*="cookie"] button', '[class*="cookie"] button',
                    '[id*="consent"] button', '[class*="consent"] button',
                ]:
                    btn = page.query_selector(selector)
                    if btn and btn.is_visible():
                        btn.click()
                        page.wait_for_timeout(500)
                        break
            except Exception:
                pass  # Cookie banner dismissal is best-effort

            # Extract rendered HTML
            html = page.content()
            final_url = page.url

            # Extract all links from the DOM
            links = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('a[href]')).map(a => ({
                    href: a.href,
                    text: (a.innerText || '').trim().substring(0, 200)
                }));
            }""")

            return {
                'html': html,
                'links': links or [],
                'final_url': final_url,
            }

        except Exception as e:
            logger.debug(f"Playwright fetch error for {url}: {e}")
            return None
        finally:
            if context:
                try:
                    context.close()
                except Exception:
                    pass

    def close(self):
        """Shut down browser and Playwright."""
        with self._lock:
            if self._browser:
                try:
                    self._browser.close()
                except Exception:
                    pass
                self._browser = None
            if self._playwright:
                try:
                    self._playwright.stop()
                except Exception:
                    pass
                self._playwright = None


class PMSystemDetector:
    """Detects property management portal systems for a given domain."""

    # Known PM software patterns
    PM_PATTERNS = {
        'appfolio': {
            'urls': [r'\.appfolio\.com', r'appfolio\.com', r'\.appf\.io', r'passport\.appf\.io'],
            'scripts': [r'apfl-', r'appfolio'],
            'classes': [r'apfl-', r'afp-listing'],
        },
        'yardi': {
            'urls': [r'\.rentcafe\.com', r'\.securecafe\.com', r'yardi\.com', r'yardiasptx'],
            'scripts': [r'yardi', r'rentcafe', r'securecafe'],
            'classes': [r'yardi-'],
        },
        'buildium': {
            'urls': [r'\.managebuilding\.com', r'buildium\.com'],
            'scripts': [r'buildium'],
            'classes': [r'buildium-'],
        },
        'rentmanager': {
            'urls': [r'\.rmresident\.com', r'rentmanager\.com'],
            'scripts': [r'rentmanager'],
            'classes': [r'rentmanager-'],
        },
        'entrata': {
            'urls': [r'\.entrata\.com', r'ips\.entrata\.com'],
            'scripts': [r'entrata'],
            'classes': [r'entrata-'],
        },
        'propertyware': {
            'urls': [r'\.propertyware\.com', r'propertyware\.com'],
            'scripts': [r'propertyware'],
            'classes': [r'propertyware-'],
        },
        'rentvine': {
            'urls': [r'\.rentvine\.com', r'rentvine\.com'],
            'scripts': [r'rentvine'],
            'classes': [r'rentvine-'],
        },
        'cincwebaxis': {
            'urls': [r'\.cincwebaxis\.com', r'cincwebaxis\.com'],
            'scripts': [r'cincwebaxis'],
            'classes': [],
        },
        'doorloop': {
            'urls': [r'\.doorloop\.com', r'app\.doorloop\.com'],
            'scripts': [r'doorloop'],
            'classes': [],
        },
        'trackhs': {
            'urls': [r'\.trackhs\.com', r'trackhs\.com'],
            'scripts': [r'trackhs'],
            'classes': [],
        },
        'propertyboss': {
            'urls': [r'\.propertyboss\.net', r'propertyboss\.net'],
            'scripts': [r'propertyboss'],
            'classes': [],
        },
        'prospectportal': {
            'urls': [r'\.prospectportal\.com', r'prospectportal\.com'],
            'scripts': [r'prospectportal'],
            'classes': [],
        },
        'mri': {
            'urls': [r'\.mriresidentconnect\.com', r'mriresidentconnect\.com', r'\.mrisoftware\.com'],
            'scripts': [r'mrisoftware', r'mriresidentconnect'],
            'classes': [],
        },
        'managego': {
            'urls': [r'\.managego\.com', r'managego\.com'],
            'scripts': [r'managego'],
            'classes': [],
        },
        'guesty': {
            'urls': [r'\.guestyowners\.com', r'guestyowners\.com', r'\.guesty\.com'],
            'scripts': [r'guesty'],
            'classes': [],
        },
        'happystays': {
            'urls': [r'\.happystays\.com', r'happystays\.com'],
            'scripts': [r'happystays'],
            'classes': [],
        },
        'realpage': {
            'urls': [r'\.loftliving\.com', r'loftliving\.com', r'\.realpage\.com', r'\.onlineleasing\.realpage\.com'],
            'scripts': [r'realpage'],
            'classes': [],
        },
        'townsq': {
            'urls': [r'\.townsq\.io', r'app\.townsq\.io'],
            'scripts': [r'townsq'],
            'classes': [],
        },
        'rentecdirect': {
            'urls': [r'\.rentecdirect\.com', r'rentecdirect\.com', r'secure\.rentecdirect\.com'],
            'scripts': [r'rentecdirect'],
            'classes': [],
        },
        'inosio': {
            'urls': [r'\.inosio\.com', r'portal\.inosio\.com'],
            'scripts': [r'inosio'],
            'classes': [],
        },
        'frontsteps': {
            'urls': [r'\.frontsteps\.com', r'app\.frontsteps\.com'],
            'scripts': [r'frontsteps'],
            'classes': [],
        },
        'turbotenant': {
            'urls': [r'\.turbotenant\.com', r'turbotenant\.com'],
            'scripts': [r'turbotenant'],
            'classes': [],
        },
        'building_engines': {
            'urls': [r'\.buildingengines\.com', r'buildingengines\.com'],
            'scripts': [r'buildingengines'],
            'classes': [],
        },
        'tenantcloud': {
            'urls': [r'\.tenantcloud\.com', r'tenantcloud\.com'],
            'scripts': [r'tenantcloud'],
            'classes': [],
        },
        'innago': {
            'urls': [r'\.innago\.com', r'my\.innago\.com'],
            'scripts': [r'innago'],
            'classes': [],
        },
        'ownerrez': {
            'urls': [r'\.ownerrez\.com', r'app\.ownerrez\.com'],
            'scripts': [r'ownerrez'],
            'classes': [],
        },
        'vantaca': {
            'urls': [r'\.vantaca\.com', r'vantaca\.com'],
            'scripts': [r'vantaca'],
            'classes': [],
        },
        'sensrportal': {
            'urls': [r'\.sensrportal\.com', r'sensrportal\.com'],
            'scripts': [r'sensrportal'],
            'classes': [],
        },
        'heropm': {
            'urls': [r'\.heropm\.com', r'portal\.heropm\.com'],
            'scripts': [r'heropm'],
            'classes': [],
        },
        'sentry': {
            'urls': [r'\.sentrymgt\.com', r'sentrymgt\.com', r'accesssentrymgt\.com'],
            'scripts': [r'sentrymgt'],
            'classes': [],
        },
    }

    # AppFolio subdomain variations to try
    APPFOLIO_SUBDOMAIN_PATTERNS = [
        '{name}',
        '{name}pm',
        '{name}propertymanagement',
        '{name}properties',
        '{name}rentals',
        '{name}realty',
        '{name}management',
        '{name}investments',
    ]

    # Secondary pages to check
    SECONDARY_PAGES = [
        '/residents/', '/residents', '/tenants/', '/tenants', '/renters/',
        '/owners/', '/owners', '/investors/',
        '/contact/', '/contact', '/about/',
        '/portal/', '/login/',
        '/pay-rent/', '/pay-rent', '/payments/', '/make-payment/',
    ]

    def __init__(self, rate_limiter: RateLimiter = None, timeout: int = 15,
                 playwright_fetcher: PlaywrightFetcher = None):
        self.rate_limiter = rate_limiter or RateLimiter(requests_per_second=0.5)
        self.timeout = timeout
        self.playwright_fetcher = playwright_fetcher
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })

    def detect(self, domain: str) -> DetectionResult:
        """Run portal system detection pipeline for a domain."""
        domain = self._normalize_domain(domain)
        result = DetectionResult(domain=domain)

        logger.info(f"Starting PM system detection for: {domain}")

        try:
            result = self._detect_portal_system(domain, result)
        except Exception as e:
            logger.error(f"Error detecting {domain}: {e}")
            result.error = str(e)

        return result

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain to consistent format."""
        domain = domain.strip().lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.rstrip('/')
        return domain

    def _fetch_page(self, url: str, allow_403: bool = False) -> Optional[tuple[str, requests.Response]]:
        """Fetch a page with per-host rate limiting and error handling."""
        parsed = urlparse(url)
        host = parsed.netloc
        self.rate_limiter.wait(host)

        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if response.status_code in (200, 201, 202):
                # Reject captcha/challenge pages that return 202 with no real content
                if response.status_code == 202 and self._is_captcha_page(response.text):
                    logger.debug(f"Got captcha challenge for {url}")
                    return None, response
                return response.text, response
            else:
                logger.debug(f"Got status {response.status_code} for {url}")
                return None, response
        except requests.RequestException as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return None, None

    def _is_captcha_page(self, content: str) -> bool:
        """Check if page is a captcha/bot challenge with no real content."""
        if len(content) < 500:
            captcha_indicators = ['sgcaptcha', 'captcha', 'challenge', 'cf-challenge']
            return any(ind in content.lower() for ind in captcha_indicators)
        return False

    @staticmethod
    def _is_cloudflare_js_challenge(response) -> bool:
        """Check if an HTTP response is a Cloudflare JS challenge that Playwright can solve.

        These return 403 with ~7KB of JS challenge code and 'Just a moment' in the title.
        Distinct from hard 403s (short error pages) and SiteGround captchas (202 + sgcaptcha).
        """
        if response is None:
            return False
        if response.status_code != 403:
            return False
        text = response.text.lower()
        content_len = len(response.text)
        # Cloudflare challenges: 403, ~5-10KB, contain "just a moment" or CF challenge markers
        if content_len < 2000 or content_len > 50000:
            return False
        cf_indicators = ['just a moment', '_cf_chl_opt', 'cf-challenge', 'challenge-platform']
        return any(ind in text for ind in cf_indicators)

    def _discover_internal_pages(self, homepage_content: str, domain: str) -> list:
        """Find internal page paths from homepage links that likely lead to resident/portal pages."""
        soup = BeautifulSoup(homepage_content, 'html.parser')
        page_keywords = ['resident', 'tenant', 'renter', 'owner', 'portal',
                        'login', 'pay', 'apply', 'leasing', 'availability']

        discovered = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            text = link.get_text().lower().strip()

            # Only internal links
            if href.startswith('/'):
                path = href
            elif domain in href.lower():
                parsed = urlparse(href)
                path = parsed.path
            else:
                continue

            # Check if link text or path contains relevant keywords
            if any(kw in text or kw in path.lower() for kw in page_keywords):
                if path and path not in discovered:
                    discovered.append(path)

        return discovered

    def _check_subdomain_exists(self, url: str) -> Optional[tuple[int, str]]:
        """Fast HEAD request to check if subdomain exists."""
        parsed = urlparse(url)
        host = parsed.netloc
        self.rate_limiter.wait(host)

        try:
            response = self.session.head(url, timeout=8, allow_redirects=False)
            redirect_url = response.headers.get('Location', '')
            return response.status_code, redirect_url
        except requests.RequestException:
            return None, None

    def _detect_portal_system(self, domain: str, result: DetectionResult) -> DetectionResult:
        """Detect the portal/property management system."""
        # Track whether we hit a Cloudflare JS challenge (Playwright can solve these)
        saw_cloudflare_challenge = False

        # Tier 1: Direct homepage fetch
        logger.debug(f"Tier 1: Fetching homepage for {domain}")
        homepage_url = f"https://www.{domain}/"
        homepage_content, response = self._fetch_page(homepage_url)
        if self._is_cloudflare_js_challenge(response):
            saw_cloudflare_challenge = True

        if homepage_content is None:
            homepage_url = f"https://{domain}/"
            homepage_content, response = self._fetch_page(homepage_url)
            if self._is_cloudflare_js_challenge(response):
                saw_cloudflare_challenge = True

        if homepage_content:
            pm_system = self._find_pm_in_content(homepage_content)
            if pm_system:
                result.portal_system = pm_system['name']
                result.portal_subdomain = pm_system.get('subdomain')
                result.confidence = "high"
                result.detection_method = "homepage_fetch"

                if pm_system['name'] == 'appfolio' and pm_system.get('subdomain'):
                    result = self._validate_appfolio_subdomain(pm_system['subdomain'], domain, result)

                return result

            custom_portal = self._find_custom_portal(homepage_content, domain)
            if custom_portal:
                result.portal_system = f"custom:{custom_portal}"
                result.confidence = "medium"
                result.detection_method = "homepage_custom_portal"
                return result

        # Tier 2: Secondary page fetch (fixed paths + discovered from homepage links)
        logger.debug(f"Tier 2: Fetching secondary pages for {domain}")

        # Build list: fixed paths + any internal links from homepage with resident/portal keywords
        pages_to_check = list(self.SECONDARY_PAGES)
        if homepage_content:
            discovered = self._discover_internal_pages(homepage_content, domain)
            pages_to_check.extend(discovered)
            # Deduplicate while preserving order
            seen = set()
            unique_pages = []
            for p in pages_to_check:
                normalized = p.rstrip('/').lower()
                if normalized not in seen:
                    seen.add(normalized)
                    unique_pages.append(p)
            pages_to_check = unique_pages

        for page in pages_to_check:
            if page.startswith('http'):
                page_url = page
            else:
                page_url = f"https://www.{domain}{page}"
            page_content, response = self._fetch_page(page_url)

            if page_content:
                pm_system = self._find_pm_in_content(page_content)
                if pm_system:
                    result.portal_system = pm_system['name']
                    result.portal_subdomain = pm_system.get('subdomain')
                    result.confidence = "high"
                    result.detection_method = f"secondary_page:{page}"

                    if pm_system['name'] == 'appfolio' and pm_system.get('subdomain'):
                        result = self._validate_appfolio_subdomain(pm_system['subdomain'], domain, result)

                    return result

                custom_portal = self._find_custom_portal(page_content, domain)
                if custom_portal:
                    result.portal_system = f"custom:{custom_portal}"
                    result.confidence = "medium"
                    result.detection_method = f"secondary_page_custom:{page}"
                    return result

        # Tier 2.5: Follow portal links to detect redirects
        logger.debug(f"Tier 2.5: Following portal links for {domain}")
        link_result = self._follow_portal_links(domain)
        if link_result:
            result.portal_system = link_result['name']
            result.portal_subdomain = link_result.get('subdomain')
            result.confidence = "high"
            result.detection_method = f"link_redirect:{link_result.get('source_link', 'unknown')}"
            return result

        # Tier 3: AppFolio subdomain probing (only accept if validated)
        logger.debug(f"Tier 3: Probing AppFolio subdomains for {domain}")
        appfolio_result = self._probe_appfolio_subdomains(domain)
        if appfolio_result and appfolio_result.get('validated', False):
            result.portal_system = 'appfolio'
            result.portal_subdomain = appfolio_result['subdomain']
            result.confidence = 'high'
            result.detection_method = "subdomain_probe"
            result.validated = True
            result.validation_website = appfolio_result.get('validation_website')
            return result
        elif appfolio_result:
            logger.debug(f"Tier 3: Subdomain {appfolio_result['subdomain']} found but not validated for {domain}, skipping")

        # Tier 4: Other platform subdomain probes
        logger.debug(f"Tier 4: Probing other platform subdomains for {domain}")
        other_result = self._probe_other_subdomains(domain)
        if other_result:
            result.portal_system = other_result['name']
            result.portal_subdomain = other_result.get('subdomain')
            result.confidence = "medium"
            result.detection_method = "subdomain_probe"
            result.validated = other_result.get('validated', False)
            return result

        # Tier 5: Playwright rendering — only for Cloudflare JS challenges
        if (saw_cloudflare_challenge
                and self.playwright_fetcher and self.playwright_fetcher.available):
            logger.debug(f"Tier 5: Playwright rendering for {domain} (Cloudflare challenge detected)")
            pw_result = self._detect_with_playwright(domain, result)
            if pw_result.portal_system and pw_result.portal_system != "unknown":
                return pw_result
        elif self.playwright_fetcher and not saw_cloudflare_challenge:
            logger.debug(f"Tier 5: Skipped for {domain} (no Cloudflare challenge)")

        # Not found
        result.portal_system = "unknown"
        result.confidence = "low"
        result.detection_method = "not_found"
        return result

    def _find_pm_in_content(self, content: str) -> Optional[dict]:
        """Search page content for PM software indicators."""
        content_lower = content.lower()

        for pm_name, patterns in self.PM_PATTERNS.items():
            for pattern in patterns['urls']:
                matches = re.findall(pattern, content_lower)
                if matches:
                    subdomain = self._extract_subdomain(content, pm_name)
                    return {'name': pm_name, 'subdomain': subdomain}

            for pattern in patterns.get('scripts', []):
                if re.search(pattern, content_lower):
                    subdomain = self._extract_subdomain(content, pm_name)
                    return {'name': pm_name, 'subdomain': subdomain}

        return None

    def _extract_subdomain(self, content: str, pm_name: str) -> Optional[str]:
        """Extract the full subdomain URL from content."""
        if pm_name == 'appfolio':
            pattern = r'(?:https?://)?([a-zA-Z0-9-]+)\.appfolio\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    if match.lower() not in ['www', 'account', 'help', 'support',
                                             'cdn', 'demo', 'demowebsitessales',
                                             'demoapmplus', '2faccount']:
                        if not match.lower().startswith('demo'):
                            return f"{match}.appfolio.com"

        elif pm_name == 'yardi':
            pattern = r'(?:https?://)?([a-zA-Z0-9-]+)\.(?:rentcafe|securecafe)\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    if match.lower() not in ['www']:
                        return f"{match}.rentcafe.com"

        elif pm_name == 'buildium':
            pattern = r'(?:https?://)?([a-zA-Z0-9-]+)\.managebuilding\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.managebuilding.com"

        elif pm_name == 'propertyware':
            pattern = r'(?:https?://)?([a-zA-Z0-9-]+)\.propertyware\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.propertyware.com"

        elif pm_name == 'rentvine':
            pattern = r'(?:https?://)?([a-zA-Z0-9-]+)\.rentvine\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.rentvine.com"

        elif pm_name == 'rentmanager':
            # RentManager URLs can be multi-level: e.g. krc.twa.rentmanager.com
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.rentmanager\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    if match.lower() not in ['www']:
                        return f"{match}.rentmanager.com"
            # Also check rmresident.com subdomains
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.rmresident\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    if match.lower() not in ['www']:
                        return f"{match}.rmresident.com"

        elif pm_name == 'entrata':
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.entrata\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    if match.lower() not in ['www', 'go', 'help', 'support']:
                        return f"{match}.entrata.com"

        elif pm_name == 'cincwebaxis':
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.cincwebaxis\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.cincwebaxis.com"

        elif pm_name == 'doorloop':
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.doorloop\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    if match.lower() not in ['www', 'app']:
                        return f"{match}.doorloop.com"
            # Also match app.doorloop.com/... paths
            pattern = r'(?:https?://)?app\.doorloop\.com'
            if re.search(pattern, content, re.IGNORECASE):
                return "app.doorloop.com"

        elif pm_name == 'trackhs':
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.trackhs\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.trackhs.com"

        elif pm_name == 'propertyboss':
            pattern = r'(?:https?://)?([a-zA-Z0-9._-]+)\.propertyboss\.net'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.propertyboss.net"

        elif pm_name == 'prospectportal':
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.prospectportal\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.prospectportal.com"

        elif pm_name == 'mri':
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.mriresidentconnect\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.mriresidentconnect.com"

        elif pm_name == 'managego':
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.managego\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.managego.com"

        elif pm_name == 'guesty':
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.guestyowners\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.guestyowners.com"

        elif pm_name == 'happystays':
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.happystays\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.happystays.com"

        elif pm_name == 'realpage':
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.loftliving\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    if match.lower() not in ['www', 'cdn']:
                        return f"{match}.loftliving.com"
            pattern = r'(?:https?://)?([a-zA-Z0-9.-]+)\.onlineleasing\.realpage\.com'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return f"{matches[0]}.onlineleasing.realpage.com"

        # Generic extraction for newer platforms
        generic_platforms = {
            'townsq': ('townsq.io', ['www']),
            'rentecdirect': ('rentecdirect.com', ['www', 'secure']),
            'inosio': ('inosio.com', ['www', 'portal']),
            'frontsteps': ('frontsteps.com', ['www', 'app']),
            'turbotenant': ('turbotenant.com', ['www', 'renter', 'rental']),
            'building_engines': ('buildingengines.com', ['www', 'app', 'connect']),
            'tenantcloud': ('tenantcloud.com', ['www', 'home']),
            'innago': ('innago.com', ['www', 'my']),
            'ownerrez': ('ownerrez.com', ['www', 'app']),
            'vantaca': ('vantaca.com', ['www', 'support']),
            'sensrportal': ('sensrportal.com', ['www']),
            'heropm': ('heropm.com', ['www', 'portal']),
            'sentry': ('sentrymgt.com', ['www']),
        }

        if pm_name in generic_platforms:
            domain_suffix, skip_subs = generic_platforms[pm_name]
            escaped = re.escape(domain_suffix)
            pattern = rf'(?:https?://)?([a-zA-Z0-9.-]+)\.{escaped}'
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    if match.lower() not in skip_subs:
                        return f"{match}.{domain_suffix}"

        return None

    def _probe_appfolio_subdomains(self, domain: str) -> Optional[dict]:
        """Probe common AppFolio subdomain patterns in parallel."""
        base_name = domain.split('.')[0]
        name_variations = self._generate_name_variations(base_name)

        subdomains_to_check = []
        for name in name_variations:
            for pattern in self.APPFOLIO_SUBDOMAIN_PATTERNS:
                subdomain = pattern.format(name=name)
                full_subdomain = f"{subdomain}.appfolio.com"
                url = f"https://{full_subdomain}/connect"
                subdomains_to_check.append((full_subdomain, subdomain, url))

        def check_subdomain(args):
            full_subdomain, subdomain, url = args
            try:
                status_code, redirect_url = self._check_subdomain_exists(url)
                if status_code is None:
                    return None

                if status_code in [200, 302]:
                    if redirect_url and 'page-not-found' in redirect_url:
                        return None

                    is_valid = (
                        status_code == 200 or
                        'account.appfolio.com' in (redirect_url or '') or
                        f'{full_subdomain}/connect/users' in (redirect_url or '') or
                        f'{subdomain}.appfolio.com' in (redirect_url or '')
                    )

                    if is_valid:
                        return full_subdomain
            except Exception:
                pass
            return None

        valid_subdomain = None
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(check_subdomain, args): args for args in subdomains_to_check}
            for future in as_completed(futures):
                result = future.result()
                if result and not valid_subdomain:
                    valid_subdomain = result
                    for f in futures:
                        f.cancel()
                    break

        if valid_subdomain:
            validation = self._validate_appfolio_subdomain(valid_subdomain, domain, DetectionResult(domain=domain))
            return {
                'subdomain': valid_subdomain,
                'validated': validation.validated,
                'validation_website': validation.validation_website,
                'confidence': 'high' if validation.validated else 'medium'
            }

        return None

    def _generate_name_variations(self, base_name: str) -> list:
        """Generate possible company name variations."""
        variations = [base_name]

        common_suffixes = [
            'properties', 'property', 'rentals', 'rental', 'realty', 'management',
            'pm', 'mgmt', 'group', 'homes', 'home', 'living', 'residential',
            'here', 'now', 'today', 'llc', 'inc', 'co', 'company',
            'solutions', 'services', 'team', 'pros', 'experts'
        ]
        for suffix in common_suffixes:
            if base_name.endswith(suffix):
                variations.append(base_name[:-len(suffix)])

        variations.append(base_name.replace('-', '').replace('_', ''))

        return list(set(variations))

    def _validate_appfolio_subdomain(self, subdomain: str, target_domain: str, result: DetectionResult) -> DetectionResult:
        """Validate AppFolio subdomain belongs to the target company."""
        url = f"https://{subdomain}/oportal/users/log_in"
        content, response = self._fetch_page(url)

        if content:
            soup = BeautifulSoup(content, 'html.parser')

            for link in soup.find_all('a', href=True):
                href = link['href'].lower()
                if target_domain in href:
                    result.validated = True
                    result.validation_website = href
                    result.confidence = "high"
                    return result

            text_content = soup.get_text().lower()
            if target_domain in text_content:
                result.validated = True
                result.confidence = "high"
                return result

            domain_patterns = [
                f"www.{target_domain}",
                f"http://{target_domain}",
                f"https://{target_domain}",
            ]
            for pattern in domain_patterns:
                if pattern in content.lower():
                    result.validated = True
                    result.validation_website = pattern
                    result.confidence = "high"
                    return result

        result.validated = False
        result.confidence = "low"
        return result

    def _probe_other_subdomains(self, domain: str) -> Optional[dict]:
        """Probe other PM platform subdomains with validation."""
        base_name = domain.split('.')[0]
        name_variations = self._generate_name_variations(base_name)

        for name in name_variations:
            # Yardi RentCafe - require 200 with real content
            url = f"https://{name}.rentcafe.com"
            content, response = self._fetch_page(url)
            if content and response and response.status_code == 200:
                if not self._is_cloudflare_challenge(content):
                    if self._validate_other_subdomain(content, domain):
                        return {'name': 'yardi', 'subdomain': f"{name}.rentcafe.com", 'validated': True}

            # Yardi SecureCafe - require 200 with real content, NO 403
            url = f"https://{name}.securecafe.com"
            content, response = self._fetch_page(url)
            if content and response and response.status_code == 200:
                if not self._is_cloudflare_challenge(content):
                    if self._validate_other_subdomain(content, domain):
                        return {'name': 'yardi', 'subdomain': f"{name}.securecafe.com", 'validated': True}

            # Buildium
            url = f"https://{name}.managebuilding.com"
            content, response = self._fetch_page(url)
            if content and response and response.status_code == 200:
                if not self._is_cloudflare_challenge(content):
                    if self._validate_other_subdomain(content, domain):
                        return {'name': 'buildium', 'subdomain': f"{name}.managebuilding.com", 'validated': True}

            # Propertyware
            url = f"https://{name}.propertyware.com"
            content, response = self._fetch_page(url)
            if content and response and response.status_code == 200:
                if not self._is_cloudflare_challenge(content):
                    if self._validate_other_subdomain(content, domain):
                        return {'name': 'propertyware', 'subdomain': f"{name}.propertyware.com", 'validated': True}

            # RentVine
            url = f"https://{name}.rentvine.com"
            content, response = self._fetch_page(url)
            if content and response and response.status_code == 200:
                if not self._is_cloudflare_challenge(content):
                    if self._validate_other_subdomain(content, domain):
                        return {'name': 'rentvine', 'subdomain': f"{name}.rentvine.com", 'validated': True}

        return None

    def _is_cloudflare_challenge(self, content: str) -> bool:
        """Check if page content is a Cloudflare challenge/block page, not real content."""
        content_lower = content.lower()
        cloudflare_indicators = [
            'just a moment...',
            'enable javascript and cookies to continue',
            '_cf_chl_opt',
            'cf-challenge',
            'challenge-platform',
        ]
        # If multiple Cloudflare indicators present and page is short, it's a challenge page
        matches = sum(1 for indicator in cloudflare_indicators if indicator in content_lower)
        return matches >= 2

    def _validate_other_subdomain(self, content: str, target_domain: str) -> bool:
        """Validate that a subdomain page belongs to the target company."""
        soup = BeautifulSoup(content, 'html.parser')

        for link in soup.find_all('a', href=True):
            href = link['href'].lower()
            if target_domain in href:
                return True

        text = soup.get_text().lower()
        if target_domain in text:
            return True

        for meta in soup.find_all('meta'):
            meta_content = meta.get('content', '').lower()
            if target_domain in meta_content:
                return True

        return False

    def _find_custom_portal(self, content: str, domain: str) -> Optional[str]:
        """Detect if company uses a custom portal system."""
        soup = BeautifulSoup(content, 'html.parser')

        portal_keywords = ['portal', 'login', 'resident', 'tenant', 'owner', 'pay rent',
                          'pay now', 'make payment', 'my account', 'sign in', 'log in',
                          'myblackstone', 'resident portal', 'owner portal']

        pm_domains = ['appfolio', 'yardi', 'rentcafe', 'securecafe', 'buildium', 'rentmanager',
                      'entrata', 'managebuilding', 'propertyware', 'rentvine', 'paylease', 'zego', 'clickpay']

        # Known non-PM platforms that should not be classified as custom portals
        non_pm_platforms = [
            'bitly.com', 'bit.ly', 'business.google.com', 'sharepoint.com',
            'salesforce.com', 'wordpress.com', 'wpengine.com', 'pantheonsite.io',
            'idxbroker.com', 'formstack.com', 'starchapter.com', 'citrixdata.com',
            'investnext.com', 'hbportal.co', 'smartvault.com', 'syncedtool.com',
            'webnode.page', 'webnode.com', 'squarespace.com', 'wix.com',
            'godaddy.com', 'weebly.com', 'hubspot.com', 'mailchimp.com',
            'typeform.com', 'jotform.com', 'google.com', 'facebook.com',
            'apscareerportal.com',
        ]

        domain_parts = domain.split('.')
        base_name = domain_parts[0] if domain_parts else domain

        for link in soup.find_all('a', href=True):
            href = link['href']
            href_lower = href.lower()
            text = link.get_text().lower()

            has_portal_keyword = any(kw in text or kw in href_lower for kw in portal_keywords)

            if has_portal_keyword:
                parsed = urlparse(href)
                if parsed.netloc:
                    link_domain = parsed.netloc.lower().replace('www.', '')

                    if any(pm in link_domain for pm in pm_domains):
                        continue

                    if link_domain == domain or link_domain == f"www.{domain}":
                        continue

                    if any(npp in link_domain for npp in non_pm_platforms):
                        continue

                    if base_name in link_domain and not link_domain.endswith(domain):
                        return parsed.netloc

        my_pattern = f"my{base_name}"
        for link in soup.find_all('a', href=True):
            href = link['href'].lower()
            if my_pattern in href:
                parsed = urlparse(link['href'])
                if parsed.netloc and not any(pm in parsed.netloc.lower() for pm in pm_domains):
                    if not any(npp in parsed.netloc.lower() for npp in non_pm_platforms):
                        return parsed.netloc

        return None

    def _follow_portal_links(self, domain: str) -> Optional[dict]:
        """Follow portal/payment links to detect PM software from redirects."""

        link_keywords = [
            'pay rent', 'pay now', 'make payment', 'tenant portal', 'resident portal',
            'owner portal', 'login', 'sign in', 'tenant login', 'resident login',
            'owner login', 'my account', 'portal', 'pay online', 'website', 'online',
            'access', 'tenant', 'resident', 'owner', 'renter', 'click here', 'go to',
            'view', 'enter', 'link', 'log in', 'sign-in', 'manage', 'account'
        ]

        pm_redirect_patterns = {
            'appfolio': [r'\.appfolio\.com', r'appfolio\.com', r'\.appf\.io', r'passport\.appf\.io'],
            'yardi': [r'\.rentcafe\.com', r'\.securecafe\.com', r'yardi\.com'],
            'buildium': [r'\.managebuilding\.com', r'buildium\.com'],
            'rentmanager': [r'\.rmresident\.com', r'rentmanager\.com'],
            'entrata': [r'\.entrata\.com'],
            'propertyware': [r'\.propertyware\.com', r'propertyware\.com'],
            'rentvine': [r'\.rentvine\.com', r'rentvine\.com'],
            'tenant_turner': [r'\.tenantturner\.com'],
            'rent_manager': [r'\.rentmanager\.com'],
            'cincwebaxis': [r'\.cincwebaxis\.com'],
            'doorloop': [r'\.doorloop\.com'],
            'trackhs': [r'\.trackhs\.com'],
            'propertyboss': [r'\.propertyboss\.net'],
            'prospectportal': [r'\.prospectportal\.com'],
            'mri': [r'\.mriresidentconnect\.com', r'\.mrisoftware\.com'],
            'managego': [r'\.managego\.com'],
            'guesty': [r'\.guestyowners\.com', r'\.guesty\.com'],
            'happystays': [r'\.happystays\.com'],
            'realpage': [r'\.loftliving\.com', r'\.realpage\.com', r'\.onlineleasing\.realpage\.com'],
            'townsq': [r'\.townsq\.io', r'app\.townsq\.io'],
            'rentecdirect': [r'\.rentecdirect\.com', r'rentecdirect\.com'],
            'inosio': [r'\.inosio\.com', r'portal\.inosio\.com'],
            'frontsteps': [r'\.frontsteps\.com', r'app\.frontsteps\.com'],
            'turbotenant': [r'\.turbotenant\.com'],
            'building_engines': [r'\.buildingengines\.com'],
            'tenantcloud': [r'\.tenantcloud\.com'],
            'innago': [r'\.innago\.com'],
            'ownerrez': [r'\.ownerrez\.com'],
            'vantaca': [r'\.vantaca\.com'],
            'sensrportal': [r'\.sensrportal\.com'],
            'heropm': [r'\.heropm\.com', r'portal\.heropm\.com'],
            'sentry': [r'\.sentrymgt\.com', r'accesssentrymgt\.com'],
        }

        pages_to_check = [
            f"https://www.{domain}/",
            f"https://{domain}/",
            f"https://www.{domain}/residents/",
            f"https://www.{domain}/tenants/",
            f"https://www.{domain}/owners/",
            f"https://www.{domain}/tenant/",
            f"https://www.{domain}/resident/",
            f"https://www.{domain}/portal/",
        ]

        portal_links = []  # Links with portal keywords — follow these for redirects
        external_links = []  # All external links — check URL patterns only

        for page_url in pages_to_check:
            content, response = self._fetch_page(page_url)
            if not content:
                continue

            soup = BeautifulSoup(content, 'html.parser')

            # Anchor text patterns that indicate incidental links, not portal links
            incidental_text_patterns = [
                'website design', 'website by', 'designed by', 'powered by',
                'built by', 'created by', 'developed by',
                'proptech', 'hud websites', 'narpm', 'national association',
                'terms of service', 'terms of use', 'privacy policy',
            ]

            for link in soup.find_all('a', href=True):
                href = link['href']
                href_lower = href.lower()
                text = link.get_text().lower().strip()

                # Skip incidental links (footer credits, industry links, etc.)
                if any(pat in text for pat in incidental_text_patterns):
                    continue

                # Check if link directly points to a PM software domain
                for pm_name, patterns in pm_redirect_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, href_lower):
                            subdomain = self._extract_subdomain_from_url(href_lower, pm_name)
                            return {
                                'name': pm_name,
                                'subdomain': subdomain,
                                'source_link': f"direct_link:{text[:20]}"
                            }

                # Normalize href for collection
                abs_href = href
                if href.startswith('/'):
                    abs_href = f"https://www.{domain}{href}"
                elif not href.startswith('http'):
                    continue

                # Collect links with portal keywords — will follow redirects
                if any(kw in text for kw in link_keywords):
                    portal_links.append({'href': abs_href, 'text': text})

                # Also collect ALL external links (different domain) for URL-pattern checking
                parsed_link = urlparse(abs_href)
                link_host = parsed_link.netloc.lower().replace('www.', '')
                if link_host and link_host != domain and link_host != f"www.{domain}":
                    external_links.append({'href': abs_href, 'text': text, 'host': link_host})

        # First: check all external link URLs against PM patterns (no fetching needed)
        seen_hosts = set()
        for link_info in external_links:
            host = link_info['host']
            if host in seen_hosts:
                continue
            seen_hosts.add(host)

            href_lower = link_info['href'].lower()
            for pm_name, patterns in pm_redirect_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, href_lower):
                        subdomain = self._extract_subdomain_from_url(href_lower, pm_name)
                        return {
                            'name': pm_name,
                            'subdomain': subdomain,
                            'source_link': f"external_link:{link_info['text'][:20]}"
                        }

        # Second: follow portal-keyword links and check redirect destinations
        seen_hrefs = set()
        for link_info in portal_links:
            href = link_info['href']
            if href in seen_hrefs:
                continue
            seen_hrefs.add(href)

            # Skip internal links and common non-PM external links
            parsed = urlparse(href)
            link_host = parsed.netloc.lower().replace('www.', '')
            if link_host == domain or link_host == f"www.{domain}":
                continue
            skip_domains = ['facebook.com', 'google.com', 'instagram.com', 'twitter.com',
                           'youtube.com', 'linkedin.com', 'yelp.com', 'bbb.org', 'zillow.com']
            if any(sd in link_host for sd in skip_domains):
                continue

            try:
                self.rate_limiter.wait()
                response = self.session.get(href, timeout=self.timeout, allow_redirects=True)

                final_url = response.url.lower()

                # Check final URL against PM patterns
                for pm_name, patterns in pm_redirect_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, final_url):
                            subdomain = self._extract_subdomain_from_url(final_url, pm_name)
                            return {
                                'name': pm_name,
                                'subdomain': subdomain,
                                'source_link': link_info['text'][:30]
                            }

                # Also check the response content for PM indicators
                if response.status_code == 200 and response.text:
                    pm_system = self._find_pm_in_content(response.text)
                    if pm_system:
                        return {
                            'name': pm_system['name'],
                            'subdomain': pm_system.get('subdomain'),
                            'source_link': f"followed_link:{link_info['text'][:20]}"
                        }

            except requests.RequestException:
                continue

        return None

    def _extract_subdomain_from_url(self, url: str, pm_name: str) -> Optional[str]:
        """Extract PM subdomain from a URL."""
        if pm_name == 'appfolio':
            match = re.search(r'([a-zA-Z0-9-]+)\.appfolio\.com', url)
            if match and match.group(1).lower() not in ['www', 'account', 'help', 'support']:
                return f"{match.group(1)}.appfolio.com"

        elif pm_name == 'yardi':
            match = re.search(r'([a-zA-Z0-9-]+)\.(?:rentcafe|securecafe)\.com', url)
            if match and match.group(1).lower() != 'www':
                return f"{match.group(1)}.rentcafe.com"

        elif pm_name == 'buildium':
            match = re.search(r'([a-zA-Z0-9-]+)\.managebuilding\.com', url)
            if match:
                return f"{match.group(1)}.managebuilding.com"

        elif pm_name == 'propertyware':
            match = re.search(r'([a-zA-Z0-9-]+)\.propertyware\.com', url)
            if match:
                return f"{match.group(1)}.propertyware.com"

        elif pm_name == 'rentvine':
            match = re.search(r'([a-zA-Z0-9-]+)\.rentvine\.com', url)
            if match:
                return f"{match.group(1)}.rentvine.com"

        elif pm_name == 'rentmanager' or pm_name == 'rent_manager':
            match = re.search(r'([a-zA-Z0-9.-]+)\.rentmanager\.com', url)
            if match and match.group(1).lower() not in ['www']:
                return f"{match.group(1)}.rentmanager.com"
            match = re.search(r'([a-zA-Z0-9.-]+)\.rmresident\.com', url)
            if match and match.group(1).lower() not in ['www']:
                return f"{match.group(1)}.rmresident.com"

        elif pm_name == 'entrata':
            match = re.search(r'([a-zA-Z0-9.-]+)\.entrata\.com', url)
            if match and match.group(1).lower() not in ['www', 'go', 'help', 'support']:
                return f"{match.group(1)}.entrata.com"

        elif pm_name == 'cincwebaxis':
            match = re.search(r'([a-zA-Z0-9.-]+)\.cincwebaxis\.com', url)
            if match:
                return f"{match.group(1)}.cincwebaxis.com"

        elif pm_name == 'doorloop':
            match = re.search(r'([a-zA-Z0-9.-]+)\.doorloop\.com', url)
            if match:
                return f"{match.group(1)}.doorloop.com"

        elif pm_name == 'trackhs':
            match = re.search(r'([a-zA-Z0-9.-]+)\.trackhs\.com', url)
            if match:
                return f"{match.group(1)}.trackhs.com"

        elif pm_name == 'propertyboss':
            match = re.search(r'([a-zA-Z0-9._-]+)\.propertyboss\.net', url)
            if match:
                return f"{match.group(1)}.propertyboss.net"

        elif pm_name == 'prospectportal':
            match = re.search(r'([a-zA-Z0-9.-]+)\.prospectportal\.com', url)
            if match:
                return f"{match.group(1)}.prospectportal.com"

        elif pm_name == 'mri':
            match = re.search(r'([a-zA-Z0-9.-]+)\.mriresidentconnect\.com', url)
            if match:
                return f"{match.group(1)}.mriresidentconnect.com"

        elif pm_name == 'managego':
            match = re.search(r'([a-zA-Z0-9.-]+)\.managego\.com', url)
            if match:
                return f"{match.group(1)}.managego.com"

        elif pm_name == 'guesty':
            match = re.search(r'([a-zA-Z0-9.-]+)\.guestyowners\.com', url)
            if match:
                return f"{match.group(1)}.guestyowners.com"

        elif pm_name == 'happystays':
            match = re.search(r'([a-zA-Z0-9.-]+)\.happystays\.com', url)
            if match:
                return f"{match.group(1)}.happystays.com"

        elif pm_name == 'realpage':
            match = re.search(r'([a-zA-Z0-9.-]+)\.loftliving\.com', url)
            if match and match.group(1).lower() not in ['www', 'cdn']:
                return f"{match.group(1)}.loftliving.com"
            match = re.search(r'([a-zA-Z0-9.-]+)\.onlineleasing\.realpage\.com', url)
            if match:
                return f"{match.group(1)}.onlineleasing.realpage.com"

        # Generic extraction for newer platforms
        generic_url_platforms = {
            'townsq': 'townsq.io',
            'rentecdirect': 'rentecdirect.com',
            'inosio': 'inosio.com',
            'frontsteps': 'frontsteps.com',
            'turbotenant': 'turbotenant.com',
            'building_engines': 'buildingengines.com',
            'tenantcloud': 'tenantcloud.com',
            'innago': 'innago.com',
            'ownerrez': 'ownerrez.com',
            'vantaca': 'vantaca.com',
            'sensrportal': 'sensrportal.com',
            'heropm': 'heropm.com',
            'sentry': 'sentrymgt.com',
        }

        if pm_name in generic_url_platforms:
            domain_suffix = generic_url_platforms[pm_name]
            escaped = re.escape(domain_suffix)
            match = re.search(rf'([a-zA-Z0-9.-]+)\.{escaped}', url)
            if match and match.group(1).lower() not in ['www']:
                return f"{match.group(1)}.{domain_suffix}"

        return None

    def _detect_with_playwright(self, domain: str, result: DetectionResult) -> DetectionResult:
        """Tier 5: Render pages with Playwright and search for PM indicators."""
        if not self.playwright_fetcher:
            return result

        # Try homepage first
        for url in [f"https://www.{domain}/", f"https://{domain}/"]:
            rendered = self.playwright_fetcher.fetch_rendered_page(url)
            if not rendered:
                continue

            # Check rendered HTML with existing content scanner
            pm_system = self._find_pm_in_content(rendered['html'])
            if pm_system:
                result.portal_system = pm_system['name']
                result.portal_subdomain = pm_system.get('subdomain')
                result.confidence = "high"
                result.detection_method = "playwright_homepage"
                if pm_system['name'] == 'appfolio' and pm_system.get('subdomain'):
                    result = self._validate_appfolio_subdomain(
                        pm_system['subdomain'], domain, result)
                return result

            # Check all DOM links against PM URL patterns
            link_result = self._check_rendered_links_for_pm(rendered['links'])
            if link_result:
                result.portal_system = link_result['name']
                result.portal_subdomain = link_result.get('subdomain')
                result.confidence = "high"
                result.detection_method = "playwright_homepage_link"
                return result

            # Homepage rendered but no PM found — try secondary pages
            break

        # Try secondary pages
        secondary = ['/residents/', '/residents', '/tenants/', '/tenants',
                     '/owners/', '/portal/', '/login/', '/pay-rent/']
        for page in secondary:
            page_url = f"https://www.{domain}{page}"
            rendered = self.playwright_fetcher.fetch_rendered_page(page_url, wait_seconds=2.0)
            if not rendered:
                continue

            pm_system = self._find_pm_in_content(rendered['html'])
            if pm_system:
                result.portal_system = pm_system['name']
                result.portal_subdomain = pm_system.get('subdomain')
                result.confidence = "high"
                result.detection_method = f"playwright_secondary:{page}"
                if pm_system['name'] == 'appfolio' and pm_system.get('subdomain'):
                    result = self._validate_appfolio_subdomain(
                        pm_system['subdomain'], domain, result)
                return result

            link_result = self._check_rendered_links_for_pm(rendered['links'])
            if link_result:
                result.portal_system = link_result['name']
                result.portal_subdomain = link_result.get('subdomain')
                result.confidence = "high"
                result.detection_method = f"playwright_secondary_link:{page}"
                return result

        return result

    def _check_rendered_links_for_pm(self, links: list) -> Optional[dict]:
        """Check a list of {href, text} dicts from Playwright against PM URL patterns."""
        for link_info in links:
            href = link_info.get('href', '').lower()
            if not href:
                continue
            for pm_name, patterns in self.PM_PATTERNS.items():
                for pattern in patterns['urls']:
                    if re.search(pattern, href):
                        subdomain = self._extract_subdomain_from_url(href, pm_name)
                        return {'name': pm_name, 'subdomain': subdomain}
        return None


class ResultsDatabase:
    """SQLite database for storing PM system detection results."""

    def __init__(self, db_path: str = "pm_system_results.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                portal_system TEXT,
                portal_subdomain TEXT,
                confidence TEXT,
                detection_method TEXT,
                validated INTEGER,
                validation_website TEXT,
                error TEXT,
                timestamp TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_domain ON results(domain)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_portal_system ON results(portal_system)
        ''')

        conn.commit()
        conn.close()

    def save_result(self, result: DetectionResult):
        """Save or update a detection result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO results
            (domain, portal_system, portal_subdomain, confidence,
             detection_method, validated, validation_website,
             error, timestamp, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            result.domain,
            result.portal_system,
            result.portal_subdomain,
            result.confidence,
            result.detection_method,
            1 if result.validated else 0,
            result.validation_website,
            result.error,
            result.timestamp,
        ))

        conn.commit()
        conn.close()

    def get_result(self, domain: str) -> Optional[DetectionResult]:
        """Get a result by domain."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM results WHERE domain = ?', (domain,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return DetectionResult(
                domain=row[1],
                portal_system=row[2],
                portal_subdomain=row[3],
                confidence=row[4],
                detection_method=row[5],
                validated=bool(row[6]),
                validation_website=row[7],
                error=row[8],
                timestamp=row[9],
            )
        return None

    def domain_exists(self, domain: str) -> bool:
        """Check if a domain has already been processed."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM results WHERE domain = ?', (domain,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists

    def export_to_csv(self, output_path: str):
        """Export all results to CSV."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM results')
        rows = cursor.fetchall()

        col_names = [description[0] for description in cursor.description]

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(col_names)
            writer.writerows(rows)

        conn.close()
        logger.info(f"Exported {len(rows)} results to {output_path}")

    def get_stats(self) -> dict:
        """Get statistics about detected systems."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}

        cursor.execute('SELECT COUNT(*) FROM results')
        stats['total'] = cursor.fetchone()[0]

        cursor.execute('''
            SELECT portal_system, COUNT(*)
            FROM results
            GROUP BY portal_system
            ORDER BY COUNT(*) DESC
        ''')
        stats['by_portal_system'] = dict(cursor.fetchall())

        cursor.execute('''
            SELECT confidence, COUNT(*)
            FROM results
            GROUP BY confidence
        ''')
        stats['by_confidence'] = dict(cursor.fetchall())

        cursor.execute('SELECT COUNT(*) FROM results WHERE validated = 1')
        stats['validated_count'] = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM results WHERE error IS NOT NULL')
        stats['error_count'] = cursor.fetchone()[0]

        conn.close()
        return stats


def process_csv(input_path: str, output_path: str, db_path: str = "pm_system_results.db",
                skip_existing: bool = True, limit: int = None, workers: int = 4,
                use_playwright: bool = True):
    """Process a CSV file of domains using parallel execution."""
    db = ResultsDatabase(db_path)

    # Read input CSV
    domains = []
    with open(input_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get('domain') or row.get('url') or row.get('website') or row.get('Domain') or row.get('URL')
            if domain:
                domains.append(domain)

    logger.info(f"Loaded {len(domains)} domains from {input_path}")

    if limit:
        domains = domains[:limit]
        logger.info(f"Limited to {limit} domains")

    # Normalize and filter domains
    normalized_domains = []
    skipped = 0
    for domain in domains:
        domain = domain.strip().lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.rstrip('/')

        if not domain:
            continue

        if skip_existing and db.domain_exists(domain):
            logger.debug(f"Skipping {domain} (already processed)")
            skipped += 1
            continue

        normalized_domains.append(domain)

    logger.info(f"Processing {len(normalized_domains)} domains ({skipped} skipped)")

    # Create shared PlaywrightFetcher for Tier 5
    pw_fetcher = None
    if use_playwright:
        pw_fetcher = PlaywrightFetcher()

    # Thread-safe counters
    processed = [0]
    errors = [0]
    counter_lock = threading.Lock()
    db_lock = threading.Lock()

    def process_domain(args):
        idx, domain = args
        detector = PMSystemDetector(playwright_fetcher=pw_fetcher)

        logger.info(f"[{idx+1}/{len(normalized_domains)}] Processing: {domain}")
        result = detector.detect(domain)

        with db_lock:
            db.save_result(result)

        with counter_lock:
            processed[0] += 1
            if result.error:
                errors[0] += 1
            if processed[0] % 10 == 0:
                logger.info(f"Progress: {processed[0]} processed, {skipped} skipped, {errors[0]} errors")

        return result

    # Process domains in parallel
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(process_domain, (i, d)) for i, d in enumerate(normalized_domains)]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error processing domain: {e}")
    finally:
        if pw_fetcher:
            pw_fetcher.close()

    # Export final results
    db.export_to_csv(output_path)

    # Print stats
    stats = db.get_stats()
    logger.info("=" * 50)
    logger.info("Detection Complete!")
    logger.info(f"Total processed: {processed[0]}")
    logger.info(f"Skipped (existing): {skipped}")
    logger.info(f"Errors: {errors[0]}")
    logger.info("=" * 50)
    logger.info("Results by Portal System:")
    for system, count in stats['by_portal_system'].items():
        logger.info(f"  {system}: {count}")
    logger.info("=" * 50)

    return stats


def save_snapshot(output_path: str, db_path: str = "pm_system_results.db"):
    """Save a snapshot of current results for future diffing."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT domain, portal_system, portal_subdomain, confidence, detection_method, validated, doors
        FROM results
        ORDER BY domain
    ''')
    rows = cursor.fetchall()
    conn.close()

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['domain', 'portal_system', 'portal_subdomain', 'confidence',
                         'detection_method', 'validated', 'doors'])
        writer.writerows(rows)

    logger.info(f"Saved snapshot of {len(rows)} domains to {output_path}")


def diff_snapshot(snapshot_path: str, db_path: str = "pm_system_results.db",
                  output_path: str = None):
    """Compare current database results against a previous snapshot.

    Reports:
    - Domains that switched PM systems
    - Domains that went from unknown to known (new detections)
    - Domains that went from known to unknown (lost detections)
    - Market share comparison
    """
    # Load previous snapshot
    prev = {}
    with open(snapshot_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            prev[row['domain']] = row

    # Load current results
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT domain, portal_system, portal_subdomain, confidence, detection_method, validated, doors
        FROM results
    ''')
    curr = {}
    for row in cursor.fetchall():
        curr[row['domain']] = dict(row)
    conn.close()

    # Categorize changes
    switches = []       # Changed from one known PM to another
    new_detections = [] # unknown -> known
    lost_detections = [] # known -> unknown
    unchanged = 0
    new_domains = []    # In current but not in snapshot
    removed_domains = [] # In snapshot but not in current

    all_domains = set(list(prev.keys()) + list(curr.keys()))

    for domain in sorted(all_domains):
        p = prev.get(domain)
        c = curr.get(domain)

        if not p:
            new_domains.append({'domain': domain, 'current': c['portal_system']})
            continue
        if not c:
            removed_domains.append({'domain': domain, 'previous': p['portal_system']})
            continue

        old_sys = p['portal_system'] or 'unknown'
        new_sys = c['portal_system'] or 'unknown'

        if old_sys == new_sys:
            unchanged += 1
            continue

        is_old_known = old_sys != 'unknown' and not old_sys.startswith('custom:')
        is_new_known = new_sys != 'unknown' and not new_sys.startswith('custom:')

        doors = c.get('doors') or p.get('doors') or 0
        try:
            doors = int(doors)
        except (ValueError, TypeError):
            doors = 0

        change = {
            'domain': domain,
            'previous': old_sys,
            'current': new_sys,
            'prev_subdomain': p.get('portal_subdomain', ''),
            'curr_subdomain': c.get('portal_subdomain', ''),
            'curr_confidence': c.get('confidence', ''),
            'doors': doors,
        }

        if is_old_known and is_new_known:
            switches.append(change)
        elif not is_old_known and is_new_known:
            new_detections.append(change)
        elif is_old_known and not is_new_known:
            lost_detections.append(change)
        else:
            unchanged += 1  # unknown -> unknown or custom -> custom

    # Market share comparison
    prev_share = {}
    curr_share = {}
    for d in prev.values():
        sys = d['portal_system'] or 'unknown'
        if sys != 'unknown' and not sys.startswith('custom:'):
            prev_share[sys] = prev_share.get(sys, 0) + 1
    for d in curr.values():
        sys = d['portal_system'] or 'unknown'
        if sys != 'unknown' and not sys.startswith('custom:'):
            curr_share[sys] = curr_share.get(sys, 0) + 1

    # Print report
    print("=" * 70)
    print("PM SYSTEM DETECTION DIFF REPORT")
    print(f"Previous snapshot: {snapshot_path}")
    print(f"Current database:  {db_path}")
    print("=" * 70)

    print(f"\nDomains in previous: {len(prev)}")
    print(f"Domains in current:  {len(curr)}")
    print(f"Unchanged:           {unchanged}")

    if switches:
        switch_doors = sum(s['doors'] for s in switches)
        print(f"\n{'=' * 70}")
        print(f"PM SYSTEM SWITCHES ({len(switches)} domains, {switch_doors:,} doors)")
        print(f"{'=' * 70}")
        for s in sorted(switches, key=lambda x: -x['doors']):
            doors_str = f"{s['doors']:,}" if s['doors'] else "?"
            print(f"  {s['domain']:40s} {doors_str:>6s} doors  {s['previous']:15s} -> {s['current']}")

    if new_detections:
        new_doors = sum(s['doors'] for s in new_detections)
        print(f"\n{'=' * 70}")
        print(f"NEW DETECTIONS: unknown -> known ({len(new_detections)} domains, {new_doors:,} doors)")
        print(f"{'=' * 70}")
        for s in sorted(new_detections, key=lambda x: -x['doors']):
            doors_str = f"{s['doors']:,}" if s['doors'] else "?"
            print(f"  {s['domain']:40s} {doors_str:>6s} doors  -> {s['current']} ({s['curr_confidence']})")

    if lost_detections:
        lost_doors = sum(s['doors'] for s in lost_detections)
        print(f"\n{'=' * 70}")
        print(f"LOST DETECTIONS: known -> unknown ({len(lost_detections)} domains, {lost_doors:,} doors)")
        print(f"{'=' * 70}")
        for s in sorted(lost_detections, key=lambda x: -x['doors']):
            doors_str = f"{s['doors']:,}" if s['doors'] else "?"
            print(f"  {s['domain']:40s} {doors_str:>6s} doors  was {s['previous']}")

    if new_domains:
        print(f"\n{'=' * 70}")
        print(f"NEW DOMAINS (not in previous snapshot): {len(new_domains)}")
        print(f"{'=' * 70}")

    if removed_domains:
        print(f"\n{'=' * 70}")
        print(f"REMOVED DOMAINS (not in current db): {len(removed_domains)}")
        print(f"{'=' * 70}")

    # Market share table — by company count and doors
    all_systems = sorted(set(list(prev_share.keys()) + list(curr_share.keys())),
                         key=lambda s: -(curr_share.get(s, 0)))

    # Aggregate doors by PM system (current only — previous snapshot may lack doors)
    curr_doors_by_sys = {}
    for d in curr.values():
        sys = d['portal_system'] or 'unknown'
        if sys != 'unknown' and not sys.startswith('custom:'):
            doors = 0
            try:
                doors = int(d.get('doors') or 0)
            except (ValueError, TypeError):
                pass
            curr_doors_by_sys[sys] = curr_doors_by_sys.get(sys, 0) + doors

    print(f"\n{'=' * 70}")
    print("MARKET SHARE COMPARISON")
    print(f"{'=' * 70}")
    print(f"  {'System':20s} {'Prev Co':>8s} {'Curr Co':>8s} {'Delta':>7s}  {'Doors':>8s}")
    print(f"  {'-' * 55}")
    prev_total = sum(prev_share.values())
    curr_total = sum(curr_share.values())
    total_doors = sum(curr_doors_by_sys.values())
    for sys in all_systems:
        p_count = prev_share.get(sys, 0)
        c_count = curr_share.get(sys, 0)
        delta = c_count - p_count
        delta_str = f"+{delta}" if delta > 0 else str(delta) if delta < 0 else "0"
        sys_doors = curr_doors_by_sys.get(sys, 0)
        doors_str = f"{sys_doors:,}" if sys_doors else "-"
        print(f"  {sys:20s} {p_count:8d} {c_count:8d} {delta_str:>7s}  {doors_str:>8s}")
    print(f"  {'-' * 55}")
    print(f"  {'TOTAL':20s} {prev_total:8d} {curr_total:8d} {curr_total - prev_total:>+7d}  {total_doors:>8,}")

    # AppFolio-specific summary
    if 'appfolio' in prev_share or 'appfolio' in curr_share:
        print(f"\n{'=' * 70}")
        print("APPFOLIO DETAIL")
        print(f"{'=' * 70}")
        af_prev = prev_share.get('appfolio', 0)
        af_curr = curr_share.get('appfolio', 0)
        af_prev_pct = af_prev / prev_total * 100 if prev_total else 0
        af_curr_pct = af_curr / curr_total * 100 if curr_total else 0
        print(f"  Previous: {af_prev} ({af_prev_pct:.1f}% of known)")
        print(f"  Current:  {af_curr} ({af_curr_pct:.1f}% of known)")

        af_doors = curr_doors_by_sys.get('appfolio', 0)
        print(f"  Doors:    {af_doors:,}")

        gained = [s for s in switches if s['current'] == 'appfolio']
        lost = [s for s in switches if s['previous'] == 'appfolio']
        if gained:
            gained_doors = sum(s['doors'] for s in gained)
            print(f"\n  Gained from other PM ({len(gained)} companies, {gained_doors:,} doors):")
            for s in sorted(gained, key=lambda x: -x['doors']):
                doors_str = f"{s['doors']:,}" if s['doors'] else "?"
                print(f"    {s['domain']:40s} {doors_str:>6s} doors  (was {s['previous']})")
        if lost:
            lost_doors = sum(s['doors'] for s in lost)
            print(f"\n  Lost to other PM ({len(lost)} companies, {lost_doors:,} doors):")
            for s in sorted(lost, key=lambda x: -x['doors']):
                doors_str = f"{s['doors']:,}" if s['doors'] else "?"
                print(f"    {s['domain']:40s} {doors_str:>6s} doors  (now {s['current']})")

    # Save diff report to CSV if requested
    if output_path:
        all_changes = []
        for s in switches:
            s['change_type'] = 'switch'
            all_changes.append(s)
        for s in new_detections:
            s['change_type'] = 'new_detection'
            all_changes.append(s)
        for s in lost_detections:
            s['change_type'] = 'lost_detection'
            all_changes.append(s)

        if all_changes:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['change_type', 'domain', 'doors', 'previous',
                                                        'current', 'prev_subdomain',
                                                        'curr_subdomain', 'curr_confidence'])
                writer.writeheader()
                writer.writerows(all_changes)
            logger.info(f"Saved {len(all_changes)} changes to {output_path}")
        else:
            logger.info("No changes detected, no CSV written")

    print(f"\n{'=' * 70}")


def main():
    parser = argparse.ArgumentParser(
        description='Detect property management portal systems for company websites'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Single URL detection
    single_parser = subparsers.add_parser('detect', help='Detect PM system for a single URL')
    single_parser.add_argument('url', help='The website URL or domain to analyze')
    single_parser.add_argument('--no-playwright', action='store_true',
                               help='Disable Playwright Tier 5 fallback')

    # Batch processing
    batch_parser = subparsers.add_parser('batch', help='Process a CSV file of domains')
    batch_parser.add_argument('input', help='Input CSV file path')
    batch_parser.add_argument('output', help='Output CSV file path')
    batch_parser.add_argument('--db', default='pm_system_results.db', help='Database file path')
    batch_parser.add_argument('--no-skip', action='store_true', help='Re-process existing domains')
    batch_parser.add_argument('--limit', type=int, help='Limit number of domains to process')
    batch_parser.add_argument('--no-playwright', action='store_true',
                               help='Disable Playwright Tier 5 fallback')

    # Export results
    export_parser = subparsers.add_parser('export', help='Export database to CSV')
    export_parser.add_argument('output', help='Output CSV file path')
    export_parser.add_argument('--db', default='pm_system_results.db', help='Database file path')

    # Show stats
    stats_parser = subparsers.add_parser('stats', help='Show detection statistics')
    stats_parser.add_argument('--db', default='pm_system_results.db', help='Database file path')

    # Snapshot current state
    snapshot_parser = subparsers.add_parser('snapshot', help='Save a snapshot CSV of current results for future diffing')
    snapshot_parser.add_argument('output', help='Output snapshot CSV file path')
    snapshot_parser.add_argument('--db', default='pm_system_results.db', help='Database file path')

    # Diff against a previous snapshot
    diff_parser = subparsers.add_parser('diff', help='Compare current results against a previous snapshot')
    diff_parser.add_argument('snapshot', help='Previous snapshot CSV file to compare against')
    diff_parser.add_argument('--db', default='pm_system_results.db', help='Database file path')
    diff_parser.add_argument('--output', help='Optional: save diff report to CSV')

    args = parser.parse_args()

    if args.command == 'detect':
        pw_fetcher = None
        if not args.no_playwright:
            pw_fetcher = PlaywrightFetcher()
        try:
            detector = PMSystemDetector(playwright_fetcher=pw_fetcher)
            result = detector.detect(args.url)
            print(json.dumps(asdict(result), indent=2))
        finally:
            if pw_fetcher:
                pw_fetcher.close()

    elif args.command == 'batch':
        process_csv(
            args.input,
            args.output,
            db_path=args.db,
            skip_existing=not args.no_skip,
            limit=args.limit,
            use_playwright=not args.no_playwright
        )

    elif args.command == 'export':
        db = ResultsDatabase(args.db)
        db.export_to_csv(args.output)

    elif args.command == 'stats':
        db = ResultsDatabase(args.db)
        stats = db.get_stats()
        print(json.dumps(stats, indent=2))

    elif args.command == 'snapshot':
        save_snapshot(args.output, args.db)

    elif args.command == 'diff':
        diff_snapshot(args.snapshot, args.db, args.output)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
