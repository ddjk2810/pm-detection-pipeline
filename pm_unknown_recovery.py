#!/usr/bin/env python3
"""
PM Unknown Recovery — Second-pass detection for domains that returned "unknown".

Reads unknowns from pm_system_results.db and applies additional detection
strategies that the main detector doesn't use:

  Strategy 1: Iframe src extraction (HIGH PRIORITY)
  Strategy 2: DNS CNAME probing (HIGH PRIORITY)
  Strategy 3: Google Custom Search fallback (MEDIUM)
  Strategy 4: Playwright iframe drilling (MEDIUM)
  Strategy 5: WordPress plugin detection (LOWER)

Usage:
    python pm_unknown_recovery.py run                         # Run all strategies on all unknowns
    python pm_unknown_recovery.py run --limit 50              # Limit to 50 domains
    python pm_unknown_recovery.py run --strategies 1,2        # Only run strategies 1 and 2
    python pm_unknown_recovery.py run --domain example.com    # Run on a single domain
    python pm_unknown_recovery.py run --dry-run               # Show what would be done, don't update DB
    python pm_unknown_recovery.py stats                       # Show recovery statistics

  Additional strategies beyond the original 5:
  Strategy 6: DNS MX/TXT record analysis (email infrastructure signals)
  Strategy 7: Sitemap.xml and robots.txt parsing for PM URLs
  Strategy 8: Meta-refresh and JS redirect detection
"""

import argparse
import json
import logging
import os
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

# Import shared classes from the main detector
from pm_system_detector import (
    DetectionResult,
    ResultsDatabase,
    RateLimiter,
    PMSystemDetector,
    PlaywrightFetcher,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ── DNS CNAME lookup ────────────────────────────────────────────────────────

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not installed — Strategy 2 (DNS CNAME) will be skipped. "
                    "Install with: pip install dnspython>=2.4.0")


# ── Constants ───────────────────────────────────────────────────────────────

# Subdomains to probe for DNS CNAME records
DNS_SUBDOMAINS = [
    'portal', 'residents', 'resident', 'pay', 'login', 'tenant',
    'tenants', 'owner', 'owners', 'rent', 'payments', 'apply',
    'leasing', 'renters',
]

# Map CNAME targets to PM system names
CNAME_PM_TARGETS = {
    'appfolio.com': 'appfolio',
    'appf.io': 'appfolio',
    'rentcafe.com': 'yardi',
    'securecafe.com': 'yardi',
    'yardi.com': 'yardi',
    'managebuilding.com': 'buildium',
    'buildium.com': 'buildium',
    'rmresident.com': 'rentmanager',
    'rentmanager.com': 'rentmanager',
    'entrata.com': 'entrata',
    'propertyware.com': 'propertyware',
    'rentvine.com': 'rentvine',
    'cincwebaxis.com': 'cincwebaxis',
    'doorloop.com': 'doorloop',
    'trackhs.com': 'trackhs',
    'propertyboss.net': 'propertyboss',
    'prospectportal.com': 'prospectportal',
    'mriresidentconnect.com': 'mri',
    'mrisoftware.com': 'mri',
    'managego.com': 'managego',
    'guestyowners.com': 'guesty',
    'guesty.com': 'guesty',
    'happystays.com': 'happystays',
    'loftliving.com': 'realpage',
    'realpage.com': 'realpage',
    'townsq.io': 'townsq',
    'rentecdirect.com': 'rentecdirect',
    'inosio.com': 'inosio',
    'frontsteps.com': 'frontsteps',
    'turbotenant.com': 'turbotenant',
    'buildingengines.com': 'building_engines',
    'tenantcloud.com': 'tenantcloud',
    'innago.com': 'innago',
    'ownerrez.com': 'ownerrez',
    'vantaca.com': 'vantaca',
    'sensrportal.com': 'sensrportal',
    'heropm.com': 'heropm',
    'sentrymgt.com': 'sentry',
}

# Iframes to skip (not PM-related)
SKIP_IFRAME_DOMAINS = [
    'google.com', 'googleapis.com', 'youtube.com', 'youtu.be',
    'facebook.com', 'fbcdn.net', 'vimeo.com', 'twitter.com',
    'recaptcha.net', 'gstatic.com', 'doubleclick.net',
    'googletagmanager.com', 'google-analytics.com', 'instagram.com',
    'linkedin.com', 'tiktok.com', 'pinterest.com', 'bing.com',
    'mapbox.com', 'openstreetmap.org', 'hotjar.com', 'intercom.io',
    'hubspot.com', 'calendly.com', 'typeform.com', 'wistia.com',
    'bidchat.io', 'bonterra.com',
]

# WordPress PM plugin paths to probe
WP_PLUGIN_PATHS = [
    '/wp-content/plugins/flavor/',                # RentCafe widget
    '/wp-content/plugins/flavor/flavor.js',
    '/wp-content/plugins/appfolio-listings/',
    '/wp-content/plugins/appfolio-listings/readme.txt',
    '/wp-content/plugins/entrata/',
    '/wp-content/plugins/rentvine/',
    '/wp-content/plugins/buildium/',
    '/wp-content/plugins/property-manager/',
    '/wp-content/plugins/flavor-flavor/',
    '/wp-content/plugins/flavor-flavor/flavor-flavor.js',
]

# WordPress shortcodes to search for in page source
WP_SHORTCODES = {
    'yardi': [r'\[rentcafe', r'\[flavor', r'rentcafe_widget', r'data-flavor'],
    'appfolio': [r'\[appfolio', r'appfolio-listings', r'appfolio_listings'],
    'entrata': [r'\[entrata'],
    'buildium': [r'\[buildium', r'\[managebuilding'],
    'rentvine': [r'\[rentvine'],
}

# WordPress plugin path -> PM system
WP_PLUGIN_PM_MAP = {
    'flavor': 'yardi',
    'appfolio-listings': 'appfolio',
    'appfolio': 'appfolio',
    'entrata': 'entrata',
    'rentvine': 'rentvine',
    'buildium': 'buildium',
}


class UnknownRecovery:
    """Second-pass detection engine for domains that returned 'unknown'."""

    def __init__(self, db_path: str = "pm_recovery_results.db",
                 main_db_path: str = "pm_system_results.db",
                 google_api_key: str = None,
                 google_cse_id: str = None,
                 use_playwright: bool = False,
                 dry_run: bool = False):
        self.db = ResultsDatabase(db_path)
        self.db_path = db_path
        self.main_db_path = main_db_path
        self.rate_limiter = RateLimiter(requests_per_second=2.0)
        self.google_api_key = google_api_key or os.environ.get('GOOGLE_API_KEY')
        self.google_cse_id = google_cse_id or os.environ.get('GOOGLE_CSE_ID')
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })

        # Playwright for Strategy 4
        self.pw_fetcher = None
        if use_playwright:
            self.pw_fetcher = PlaywrightFetcher()

        # Reuse the main detector for pattern matching
        self.detector = PMSystemDetector(rate_limiter=self.rate_limiter)

        # Track stats
        self.stats = {
            'total_unknowns': 0,
            'attempted': 0,
            'recovered': 0,
            'by_strategy': {},
            'by_system': {},
        }

    def get_unknown_domains(self, limit: int = None) -> list[str]:
        """Fetch all domains with portal_system='unknown' from the main source of truth DB."""
        conn = sqlite3.connect(self.main_db_path)
        cursor = conn.cursor()
        query = "SELECT domain FROM results WHERE portal_system = 'unknown' ORDER BY domain"
        if limit:
            query += f" LIMIT {limit}"
        cursor.execute(query)
        domains = [row[0] for row in cursor.fetchall()]
        conn.close()
        return domains

    def run(self, domains: list[str] = None, strategies: list[int] = None,
            limit: int = None, workers: int = 4):
        """Run recovery strategies on unknown domains."""
        if domains is None:
            domains = self.get_unknown_domains(limit=limit)

        self.stats['total_unknowns'] = len(domains)
        logger.info(f"Starting recovery on {len(domains)} unknown domains")
        if self.dry_run:
            logger.info("DRY RUN — database will not be updated")

        if strategies is None:
            strategies = [1, 2, 3, 4, 5, 6, 7, 8]

        logger.info(f"Active strategies: {strategies}")

        # DNS strategies (2 and 6) are fast and parallelizable — run them first
        dns_strategies = [s for s in strategies if s in (2, 6)]
        if dns_strategies and DNS_AVAILABLE:
            logger.info(f"═══ Running DNS strategies {dns_strategies} (batch) ═══")
            self._run_dns_batch(domains, dns_strategies, workers=min(workers, 8))
            # Remove recovered domains from list
            domains = [d for d in domains if not self._is_recovered(d)]
            logger.info(f"After DNS: {len(domains)} unknowns remaining")

        # Run remaining strategies sequentially per domain (exclude DNS batch strategies)
        remaining_strategies = [s for s in strategies if s not in (2, 6)]
        if remaining_strategies and domains:
            logger.info(f"═══ Running strategies {remaining_strategies} on {len(domains)} remaining domains ═══")
            self._run_per_domain(domains, remaining_strategies, workers=workers)

        # Print summary
        self._print_summary()

    def _is_recovered(self, domain: str) -> bool:
        """Check if domain was already recovered (no longer unknown)."""
        result = self.db.get_result(domain)
        return result is not None and result.portal_system != 'unknown'

    def _run_dns_batch(self, domains: list[str], dns_strategies: list[int],
                       workers: int = 8):
        """Run DNS-based strategies on all domains in parallel."""
        recovered = [0]

        def probe_domain(domain):
            for strat in dns_strategies:
                if strat == 2:
                    result = self._strategy_dns_cname(domain)
                elif strat == 6:
                    result = self._strategy_dns_mx_txt(domain)
                else:
                    continue
                if result:
                    return domain, result
            return domain, None

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(probe_domain, d): d for d in domains}
            for future in as_completed(futures):
                domain, result = future.result()
                self.stats['attempted'] += 1
                if result:
                    recovered[0] += 1
                    self._save_recovery(domain, result)

        logger.info(f"DNS strategies recovered {recovered[0]} domains")

    def _run_per_domain(self, domains: list[str], strategies: list[int],
                        workers: int = 4):
        """Run HTTP-based strategies per domain (rate-limited)."""
        counter_lock = threading.Lock()
        processed = [0]

        def process_domain(domain):
            result = self._try_strategies(domain, strategies)
            with counter_lock:
                processed[0] += 1
                if processed[0] % 25 == 0:
                    logger.info(f"Progress: {processed[0]}/{len(domains)} processed, "
                                f"{self.stats['recovered']} recovered so far")
            return domain, result

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(process_domain, d): d for d in domains}
            for future in as_completed(futures):
                try:
                    domain, result = future.result()
                    if result:
                        self._save_recovery(domain, result)
                except Exception as e:
                    logger.error(f"Error processing domain: {e}")

    def _try_strategies(self, domain: str, strategies: list[int]) -> Optional[dict]:
        """Try each strategy in order on a single domain. Return first match."""
        for strategy_num in strategies:
            try:
                result = None
                if strategy_num == 1:
                    result = self._strategy_iframe_extraction(domain)
                elif strategy_num == 3:
                    result = self._strategy_google_search(domain)
                elif strategy_num == 4:
                    result = self._strategy_playwright_iframes(domain)
                elif strategy_num == 5:
                    result = self._strategy_wordpress_detection(domain)
                elif strategy_num == 6:
                    result = self._strategy_dns_mx_txt(domain)
                elif strategy_num == 7:
                    result = self._strategy_sitemap(domain)
                elif strategy_num == 8:
                    result = self._strategy_meta_redirect(domain)
                # Strategy 2 is handled in batch mode above

                if result:
                    self.stats['attempted'] += 1
                    return result
            except Exception as e:
                logger.debug(f"Strategy {strategy_num} error for {domain}: {e}")

        self.stats['attempted'] += 1
        return None

    def _save_recovery(self, domain: str, recovery: dict):
        """Save a successful recovery to the recovery DB (separate from main source of truth)."""
        strategy_name = recovery.get('strategy', 'unknown_strategy')
        pm_name = recovery['name']

        self.stats['recovered'] += 1
        self.stats['by_strategy'][strategy_name] = self.stats['by_strategy'].get(strategy_name, 0) + 1
        self.stats['by_system'][pm_name] = self.stats['by_system'].get(pm_name, 0) + 1

        logger.info(f"  RECOVERED: {domain} -> {pm_name} "
                     f"(subdomain={recovery.get('subdomain')}, strategy={strategy_name})")

        if self.dry_run:
            return

        result = DetectionResult(
            domain=domain,
            portal_system=pm_name,
            portal_subdomain=recovery.get('subdomain'),
            confidence=recovery.get('confidence', 'medium'),
            detection_method=f"recovery:{strategy_name}",
            validated=recovery.get('validated', False),
            validation_website=recovery.get('validation_website'),
        )
        self.db.save_result(result)

    # ── Strategy 1: Iframe src extraction ───────────────────────────────────

    def _strategy_iframe_extraction(self, domain: str) -> Optional[dict]:
        """Extract iframe src URLs from homepage and secondary pages, match against PM patterns."""
        pages = [
            f"https://www.{domain}/",
            f"https://{domain}/",
            f"https://www.{domain}/residents/",
            f"https://www.{domain}/tenants/",
            f"https://www.{domain}/owners/",
            f"https://www.{domain}/pay-rent/",
            f"https://www.{domain}/portal/",
        ]

        for page_url in pages:
            try:
                parsed = urlparse(page_url)
                self.rate_limiter.wait(parsed.netloc)
                response = self.session.get(page_url, timeout=15, allow_redirects=True)
                if response.status_code != 200:
                    continue

                content = response.text
                iframe_result = self._check_iframes_in_content(content, domain)
                if iframe_result:
                    iframe_result['strategy'] = 'iframe_extraction'
                    return iframe_result

            except requests.RequestException:
                continue

        return None

    def _check_iframes_in_content(self, content: str, domain: str) -> Optional[dict]:
        """Extract iframe src URLs from HTML and check for PM indicators."""
        soup = BeautifulSoup(content, 'html.parser')
        iframes = soup.find_all('iframe')

        if not iframes:
            return None

        for iframe in iframes:
            # Check src, data-src, and data-lazy-src (lazy-loaded iframes)
            src = (iframe.get('src', '').strip() or
                   iframe.get('data-src', '').strip() or
                   iframe.get('data-lazy-src', '').strip())
            if not src or src.startswith('about:') or src.startswith('javascript:'):
                continue

            # Make absolute
            if src.startswith('//'):
                src = 'https:' + src
            elif not src.startswith('http'):
                continue

            # Skip non-PM iframes
            iframe_host = urlparse(src).netloc.lower()
            if any(skip in iframe_host for skip in SKIP_IFRAME_DOMAINS):
                continue

            # Check iframe URL against PM patterns
            src_lower = src.lower()
            for pm_name, patterns in PMSystemDetector.PM_PATTERNS.items():
                for pattern in patterns['urls']:
                    if re.search(pattern, src_lower):
                        subdomain = self.detector._extract_subdomain_from_url(src_lower, pm_name)
                        return {
                            'name': pm_name,
                            'subdomain': subdomain,
                            'confidence': 'high',
                            'source': f'iframe_src:{src[:80]}',
                        }

            # Fetch iframe content and scan it
            try:
                self.rate_limiter.wait(iframe_host)
                resp = self.session.get(src, timeout=10, allow_redirects=True)
                if resp.status_code == 200 and resp.text:
                    # Check final URL for PM domains
                    final_url = resp.url.lower()
                    for pm_name, patterns in PMSystemDetector.PM_PATTERNS.items():
                        for pattern in patterns['urls']:
                            if re.search(pattern, final_url):
                                subdomain = self.detector._extract_subdomain_from_url(final_url, pm_name)
                                return {
                                    'name': pm_name,
                                    'subdomain': subdomain,
                                    'confidence': 'high',
                                    'source': f'iframe_redirect:{final_url[:80]}',
                                }

                    # Check iframe page content
                    pm_system = self.detector._find_pm_in_content(resp.text)
                    if pm_system:
                        return {
                            'name': pm_system['name'],
                            'subdomain': pm_system.get('subdomain'),
                            'confidence': 'high',
                            'source': f'iframe_content:{src[:80]}',
                        }
            except requests.RequestException:
                pass

        return None

    # ── Strategy 2: DNS CNAME probing ───────────────────────────────────────

    def _strategy_dns_cname(self, domain: str) -> Optional[dict]:
        """Check DNS CNAME records on common subdomains for PM platform pointers."""
        if not DNS_AVAILABLE:
            return None

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        # Email/DKIM patterns to filter out — these indicate PM usage for email
        # but don't give us portal subdomains
        email_auth_patterns = ['_domainkey', '_dkim', '_dmarc', 'dkim', 'spf', 'selector']

        # Track CNAME targets to detect wildcards (if all point to same target, it's a wildcard)
        cname_targets_seen = {}

        for sub in DNS_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            try:
                answers = resolver.resolve(fqdn, 'CNAME')
                for rdata in answers:
                    cname_target = str(rdata.target).rstrip('.').lower()

                    # Track for wildcard detection
                    cname_targets_seen[sub] = cname_target

                    # Skip email authentication records
                    if any(pat in cname_target for pat in email_auth_patterns):
                        continue

                    # Check if CNAME points to a known PM platform
                    for pm_domain, pm_name in CNAME_PM_TARGETS.items():
                        if cname_target.endswith(pm_domain):
                            return {
                                'name': pm_name,
                                'subdomain': cname_target,
                                'confidence': 'high',
                                'validated': True,
                                'strategy': 'dns_cname',
                                'source': f'CNAME:{fqdn}->{cname_target}',
                            }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.resolver.Timeout,
                    dns.name.EmptyLabel, Exception):
                continue

        # Check if DKIM wildcard records point to a PM platform — lower confidence
        # (e.g., *.domain.com -> dkim.yardi.com means they use Yardi for email)
        if cname_targets_seen:
            unique_targets = set(cname_targets_seen.values())
            # If most/all subdomains point to the same DKIM target, it's a wildcard
            if len(unique_targets) == 1:
                target = list(unique_targets)[0]
                if any(pat in target for pat in email_auth_patterns):
                    for pm_domain, pm_name in CNAME_PM_TARGETS.items():
                        if target.endswith(pm_domain):
                            return {
                                'name': pm_name,
                                'subdomain': None,  # Don't use DKIM record as subdomain
                                'confidence': 'medium',
                                'validated': False,
                                'strategy': 'dns_cname_dkim',
                                'source': f'DKIM_WILDCARD:*.{domain}->{target}',
                            }

        # Also check A/AAAA records that might point to PM platforms via
        # canonical name (some DNS setups use CNAME chains)
        for sub in DNS_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            try:
                answers = resolver.resolve(fqdn, 'A')
                canonical = str(answers.canonical_name).rstrip('.').lower()
                if canonical != fqdn.lower():
                    # Skip email auth records
                    if any(pat in canonical for pat in email_auth_patterns):
                        continue
                    for pm_domain, pm_name in CNAME_PM_TARGETS.items():
                        if canonical.endswith(pm_domain):
                            return {
                                'name': pm_name,
                                'subdomain': canonical,
                                'confidence': 'high',
                                'validated': True,
                                'strategy': 'dns_cname',
                                'source': f'A_CANONICAL:{fqdn}->{canonical}',
                            }
            except Exception:
                continue

        return None

    # ── Strategy 3: Google Custom Search ────────────────────────────────────

    def _strategy_google_search(self, domain: str) -> Optional[dict]:
        """Use Google Custom Search to find PM software mentions for blocked sites."""
        if not self.google_api_key or not self.google_cse_id:
            return None

        pm_terms = ('"appfolio" OR "rentcafe" OR "managebuilding" OR "propertyware" '
                    'OR "rentvine" OR "rmresident" OR "entrata" OR "buildium"')
        query = f'site:{domain} {pm_terms}'

        try:
            time.sleep(1)  # Rate limit: 1 query/sec
            response = self.session.get(
                'https://www.googleapis.com/customsearch/v1',
                params={
                    'key': self.google_api_key,
                    'cx': self.google_cse_id,
                    'q': query,
                    'num': 5,
                },
                timeout=15,
            )
            if response.status_code != 200:
                logger.debug(f"Google search returned {response.status_code} for {domain}")
                return None

            data = response.json()
            items = data.get('items', [])

            for item in items:
                # Check snippet and title for PM indicators
                text = f"{item.get('title', '')} {item.get('snippet', '')} {item.get('link', '')}"
                pm_system = self.detector._find_pm_in_content(text)
                if pm_system:
                    return {
                        'name': pm_system['name'],
                        'subdomain': pm_system.get('subdomain'),
                        'confidence': 'medium',
                        'strategy': 'google_search',
                        'source': f'google:{item.get("link", "")[:80]}',
                    }

        except Exception as e:
            logger.debug(f"Google search error for {domain}: {e}")

        return None

    # ── Strategy 4: Playwright iframe drilling ──────────────────────────────

    def _strategy_playwright_iframes(self, domain: str) -> Optional[dict]:
        """Use Playwright to render page, extract JS-injected iframes, and scan them."""
        if not self.pw_fetcher or not self.pw_fetcher.available:
            return None

        for url in [f"https://www.{domain}/", f"https://{domain}/"]:
            rendered = self.pw_fetcher.fetch_rendered_page(url, wait_seconds=3.0)
            if not rendered:
                continue

            html = rendered['html']

            # Extract iframe srcs from rendered DOM via the HTML
            # (The main Playwright fetcher doesn't extract iframes, so we parse the rendered HTML)
            result = self._check_iframes_in_content(html, domain)
            if result:
                result['strategy'] = 'playwright_iframe'
                return result

            # Also check rendered links (same as Tier 5 but we're here for iframe focus)
            link_result = self.detector._check_rendered_links_for_pm(rendered['links'])
            if link_result:
                return {
                    'name': link_result['name'],
                    'subdomain': link_result.get('subdomain'),
                    'confidence': 'high',
                    'strategy': 'playwright_iframe',
                    'source': 'playwright_rendered_link',
                }

        # Try secondary pages
        for page in ['/residents/', '/tenants/', '/pay-rent/', '/portal/']:
            page_url = f"https://www.{domain}{page}"
            rendered = self.pw_fetcher.fetch_rendered_page(page_url, wait_seconds=2.0)
            if not rendered:
                continue

            result = self._check_iframes_in_content(rendered['html'], domain)
            if result:
                result['strategy'] = 'playwright_iframe'
                return result

        return None

    # ── Strategy 5: WordPress plugin detection ──────────────────────────────

    def _strategy_wordpress_detection(self, domain: str) -> Optional[dict]:
        """Detect PM software via WordPress plugin paths and shortcodes."""
        # First check if it's a WordPress site (check homepage for WP indicators)
        homepage_url = f"https://www.{domain}/"
        try:
            parsed = urlparse(homepage_url)
            self.rate_limiter.wait(parsed.netloc)
            response = self.session.get(homepage_url, timeout=15, allow_redirects=True)
            if response.status_code != 200:
                return None
            content = response.text
        except requests.RequestException:
            return None

        content_lower = content.lower()
        is_wordpress = ('wp-content' in content_lower or
                        'wp-includes' in content_lower or
                        'wordpress' in content_lower or
                        'wp-json' in content_lower)

        if not is_wordpress:
            return None

        logger.debug(f"WordPress detected for {domain}, checking plugins and shortcodes")

        # Check for PM shortcodes in the page source
        for pm_name, patterns in WP_SHORTCODES.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    return {
                        'name': pm_name,
                        'subdomain': None,
                        'confidence': 'medium',
                        'strategy': 'wp_shortcode',
                        'source': f'shortcode:{pattern}',
                    }

        # Probe known PM plugin paths
        for plugin_path in WP_PLUGIN_PATHS:
            probe_url = f"https://www.{domain}{plugin_path}"
            try:
                parsed = urlparse(probe_url)
                self.rate_limiter.wait(parsed.netloc)
                resp = self.session.head(probe_url, timeout=8, allow_redirects=True)
                if resp.status_code == 200:
                    # Determine which PM system from the path
                    for plugin_key, pm_name in WP_PLUGIN_PM_MAP.items():
                        if plugin_key in plugin_path:
                            return {
                                'name': pm_name,
                                'subdomain': None,
                                'confidence': 'medium',
                                'strategy': 'wp_plugin',
                                'source': f'plugin_path:{plugin_path}',
                            }
            except requests.RequestException:
                continue

        # Check WP REST API for active plugins (some sites expose this)
        wp_api_url = f"https://www.{domain}/wp-json/wp/v2/plugins"
        try:
            self.rate_limiter.wait(f"www.{domain}")
            resp = self.session.get(wp_api_url, timeout=8)
            if resp.status_code == 200:
                try:
                    plugins = resp.json()
                    for plugin in plugins:
                        plugin_name = str(plugin.get('plugin', '') + ' ' +
                                          plugin.get('name', '')).lower()
                        for plugin_key, pm_name in WP_PLUGIN_PM_MAP.items():
                            if plugin_key in plugin_name:
                                return {
                                    'name': pm_name,
                                    'subdomain': None,
                                    'confidence': 'medium',
                                    'strategy': 'wp_api',
                                    'source': f'wp_api:{plugin_name[:60]}',
                                }
                except (ValueError, TypeError):
                    pass
        except requests.RequestException:
            pass

        return None

    # ── Strategy 6: DNS MX/TXT record analysis ────────────────────────────

    def _strategy_dns_mx_txt(self, domain: str) -> Optional[dict]:
        """Check MX and TXT records for PM platform indicators.

        If a company's email goes through a PM platform, MX/SPF/TXT records
        will reference that platform's domain.
        """
        if not DNS_AVAILABLE:
            return None

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        # Check MX records
        try:
            answers = resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_host = str(rdata.exchange).rstrip('.').lower()
                for pm_domain, pm_name in CNAME_PM_TARGETS.items():
                    if mx_host.endswith(pm_domain):
                        return {
                            'name': pm_name,
                            'subdomain': None,
                            'confidence': 'medium',
                            'validated': False,
                            'strategy': 'dns_mx',
                            'source': f'MX:{domain}->{mx_host}',
                        }
        except Exception:
            pass

        # SPF-specific PM indicators — ordered by specificity (most specific first)
        # PropertyWare is a RealPage product, so their SPF includes realpage.com;
        # we use more specific identifiers to avoid misattribution.
        SPF_PM_INDICATORS = [
            ('asp-spf1.yardi.com', 'yardi'),
            ('asp-spf2.yardi.com', 'yardi'),
            ('imail01.asp1.yardi.com', 'yardi'),
            ('_spf.rentmanager.com', 'rentmanager'),
            ('mail.rentmanager.com', 'rentmanager'),
            ('propertyware.com', 'propertyware'),
            ('_spf.realpage.com', 'realpage'),
            ('include:asp-spf', 'yardi'),  # Yardi ASP SPF pattern
            ('appfolio.com', 'appfolio'),
            ('managebuilding.com', 'buildium'),
            ('entrata.com', 'entrata'),
            ('rentvine.com', 'rentvine'),
            ('managego.com', 'managego'),
        ]

        # Check TXT records (SPF often includes PM platform mail servers)
        try:
            answers = resolver.resolve(domain, 'TXT')
            all_txt = ' '.join(str(rdata).lower() for rdata in answers)

            # Check SPF-specific patterns (most specific first)
            for indicator, pm_name in SPF_PM_INDICATORS:
                if indicator in all_txt:
                    return {
                        'name': pm_name,
                        'subdomain': None,
                        'confidence': 'low',
                        'validated': False,
                        'strategy': 'dns_spf',
                        'source': f'SPF:{indicator}',
                    }
        except Exception:
            pass

        return None

    # ── Strategy 7: Sitemap.xml and robots.txt parsing ──────────────────────

    def _strategy_sitemap(self, domain: str) -> Optional[dict]:
        """Parse sitemap.xml and robots.txt for PM platform URLs."""
        # Check robots.txt for sitemap location and PM URLs
        for base in [f"https://www.{domain}", f"https://{domain}"]:
            robots_url = f"{base}/robots.txt"
            try:
                parsed = urlparse(robots_url)
                self.rate_limiter.wait(parsed.netloc)
                resp = self.session.get(robots_url, timeout=10, allow_redirects=True)
                if resp.status_code == 200 and resp.text:
                    # Check robots.txt content for PM URLs
                    pm_system = self.detector._find_pm_in_content(resp.text)
                    if pm_system:
                        return {
                            'name': pm_system['name'],
                            'subdomain': pm_system.get('subdomain'),
                            'confidence': 'medium',
                            'strategy': 'robots_txt',
                            'source': 'robots.txt',
                        }
            except requests.RequestException:
                pass

            # Check sitemap.xml
            sitemap_url = f"{base}/sitemap.xml"
            try:
                self.rate_limiter.wait(parsed.netloc)
                resp = self.session.get(sitemap_url, timeout=10, allow_redirects=True)
                if resp.status_code == 200 and resp.text:
                    # Check sitemap content for PM URLs
                    pm_system = self.detector._find_pm_in_content(resp.text)
                    if pm_system:
                        return {
                            'name': pm_system['name'],
                            'subdomain': pm_system.get('subdomain'),
                            'confidence': 'medium',
                            'strategy': 'sitemap',
                            'source': 'sitemap.xml',
                        }
            except requests.RequestException:
                pass

            # Only try one base URL if we got a response
            break

        return None

    # ── Strategy 8: Meta-refresh and JS redirect detection ──────────────────

    def _strategy_meta_redirect(self, domain: str) -> Optional[dict]:
        """Detect PM software via meta-refresh tags and JS redirects on portal pages.

        Some sites use meta-refresh or JS window.location redirects on their
        portal/resident pages instead of HTTP redirects or regular links.
        """
        portal_paths = [
            '/portal', '/portal/', '/resident-portal', '/resident-portal/',
            '/tenant-portal', '/tenant-portal/', '/owner-portal', '/owner-portal/',
            '/pay', '/pay/', '/resident-login', '/resident-login/',
            '/tenant-login', '/tenant-login/', '/owner-login', '/owner-login/',
        ]

        for path in portal_paths:
            url = f"https://www.{domain}{path}"
            try:
                parsed = urlparse(url)
                self.rate_limiter.wait(parsed.netloc)
                resp = self.session.get(url, timeout=10, allow_redirects=True)

                if resp.status_code != 200:
                    continue

                content = resp.text
                content_lower = content.lower()

                # Check final URL after redirects
                final_url = resp.url.lower()
                for pm_name, patterns in PMSystemDetector.PM_PATTERNS.items():
                    for pattern in patterns['urls']:
                        if re.search(pattern, final_url):
                            subdomain = self.detector._extract_subdomain_from_url(final_url, pm_name)
                            return {
                                'name': pm_name,
                                'subdomain': subdomain,
                                'confidence': 'high',
                                'strategy': 'meta_redirect',
                                'source': f'redirect:{path}->{final_url[:80]}',
                            }

                # Check meta refresh tags
                meta_refresh = re.search(
                    r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>\s]+)',
                    content_lower
                )
                if meta_refresh:
                    refresh_url = meta_refresh.group(1)
                    for pm_name, patterns in PMSystemDetector.PM_PATTERNS.items():
                        for pattern in patterns['urls']:
                            if re.search(pattern, refresh_url):
                                subdomain = self.detector._extract_subdomain_from_url(refresh_url, pm_name)
                                return {
                                    'name': pm_name,
                                    'subdomain': subdomain,
                                    'confidence': 'high',
                                    'strategy': 'meta_refresh',
                                    'source': f'meta_refresh:{path}->{refresh_url[:80]}',
                                }

                # Check JS redirects (window.location, window.location.href, location.replace)
                js_redirects = re.findall(
                    r'(?:window\.location(?:\.href)?\s*=\s*["\']|location\.replace\s*\(\s*["\'])([^"\']+)',
                    content
                )
                for redirect_url in js_redirects:
                    redirect_lower = redirect_url.lower()
                    for pm_name, patterns in PMSystemDetector.PM_PATTERNS.items():
                        for pattern in patterns['urls']:
                            if re.search(pattern, redirect_lower):
                                subdomain = self.detector._extract_subdomain_from_url(redirect_lower, pm_name)
                                return {
                                    'name': pm_name,
                                    'subdomain': subdomain,
                                    'confidence': 'high',
                                    'strategy': 'js_redirect',
                                    'source': f'js_redirect:{path}->{redirect_url[:80]}',
                                }

                # Also run standard PM content check on the page
                pm_system = self.detector._find_pm_in_content(content)
                if pm_system:
                    return {
                        'name': pm_system['name'],
                        'subdomain': pm_system.get('subdomain'),
                        'confidence': 'high',
                        'strategy': 'portal_path',
                        'source': f'portal_path:{path}',
                    }

            except requests.RequestException:
                continue

        return None

    # ── Summary ─────────────────────────────────────────────────────────────

    def _print_summary(self):
        """Print recovery summary."""
        logger.info("=" * 60)
        logger.info("RECOVERY COMPLETE")
        logger.info(f"  Total unknowns processed: {self.stats['total_unknowns']}")
        logger.info(f"  Recovered: {self.stats['recovered']}")
        if self.stats['total_unknowns'] > 0:
            pct = self.stats['recovered'] / self.stats['total_unknowns'] * 100
            logger.info(f"  Recovery rate: {pct:.1f}%")
        logger.info("")

        if self.stats['by_strategy']:
            logger.info("  By strategy:")
            for strategy, count in sorted(self.stats['by_strategy'].items(),
                                           key=lambda x: -x[1]):
                logger.info(f"    {strategy}: {count}")

        if self.stats['by_system']:
            logger.info("")
            logger.info("  By PM system:")
            for system, count in sorted(self.stats['by_system'].items(),
                                         key=lambda x: -x[1]):
                logger.info(f"    {system}: {count}")

        logger.info("=" * 60)

        if self.dry_run:
            logger.info("DRY RUN — no changes were saved to the database")

    def close(self):
        """Clean up resources."""
        if self.pw_fetcher:
            self.pw_fetcher.close()


def consolidate_recovery(recovery_db_path: str = "pm_recovery_results.db",
                         main_db_path: str = "pm_system_results.db",
                         dry_run: bool = False):
    """Merge recovery results into the main source of truth DB.

    Only merges domains where the main DB has 'unknown' or no entry at all.
    Never overwrites existing non-unknown detections in the main DB.
    """
    recovery_conn = sqlite3.connect(recovery_db_path)
    main_conn = sqlite3.connect(main_db_path)
    rc = recovery_conn.cursor()
    mc = main_conn.cursor()

    # Get all non-unknown recoveries
    rc.execute("""
        SELECT domain, portal_system, portal_subdomain, confidence,
               detection_method, validated, validation_website, error, timestamp
        FROM results
        WHERE portal_system IS NOT NULL AND portal_system != 'unknown'
        ORDER BY domain
    """)
    recoveries = rc.fetchall()

    merged = 0
    skipped_existing = 0
    skipped_no_entry = 0

    logger.info(f"Consolidating {len(recoveries)} recovery results into {main_db_path}")

    for row in recoveries:
        domain = row[0]
        recovery_system = row[1]

        # Check what the main DB has for this domain
        mc.execute("SELECT portal_system, detection_method, confidence FROM results WHERE domain = ?",
                   (domain,))
        main_row = mc.fetchone()

        if main_row is None:
            # Domain not in main DB at all — skip (we only supplement existing unknowns)
            skipped_no_entry += 1
            continue

        main_system = main_row[0]

        if main_system and main_system != 'unknown':
            # Main DB already has a real detection — defer to it
            skipped_existing += 1
            logger.debug(f"  SKIP: {domain} — main DB has {main_system} ({main_row[1]}), "
                         f"recovery has {recovery_system}")
            continue

        # Main DB has 'unknown' — merge in the recovery result
        if dry_run:
            logger.info(f"  WOULD MERGE: {domain} -> {recovery_system} "
                        f"(confidence={row[3]}, method={row[4]})")
        else:
            mc.execute("""
                UPDATE results SET
                    portal_system = ?,
                    portal_subdomain = ?,
                    confidence = ?,
                    detection_method = ?,
                    validated = ?,
                    validation_website = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE domain = ?
            """, (row[1], row[2], row[3], row[4], row[5], row[6], domain))
            logger.info(f"  MERGED: {domain} -> {recovery_system} "
                        f"(confidence={row[3]}, method={row[4]})")
        merged += 1

    if not dry_run:
        main_conn.commit()

    recovery_conn.close()
    main_conn.close()

    logger.info("=" * 60)
    logger.info("CONSOLIDATION COMPLETE")
    logger.info(f"  Recovery candidates: {len(recoveries)}")
    logger.info(f"  Merged into main DB: {merged}")
    logger.info(f"  Skipped (main has detection): {skipped_existing}")
    logger.info(f"  Skipped (not in main DB): {skipped_no_entry}")
    if dry_run:
        logger.info("  (DRY RUN — no changes written)")
    logger.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Recover PM system detections for domains that returned "unknown"'
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Run recovery
    run_parser = subparsers.add_parser('run', help='Run recovery strategies on unknown domains')
    run_parser.add_argument('--db', default='pm_recovery_results.db', help='Recovery database file path')
    run_parser.add_argument('--main-db', default='pm_system_results.db', help='Main source of truth database')
    run_parser.add_argument('--limit', type=int, help='Limit number of domains to process')
    run_parser.add_argument('--domain', help='Run on a single domain')
    run_parser.add_argument('--strategies', help='Comma-separated strategy numbers (e.g., 1,2)')
    run_parser.add_argument('--dry-run', action='store_true', help='Show results without updating DB')
    run_parser.add_argument('--workers', type=int, default=4, help='Number of parallel workers')
    run_parser.add_argument('--google-api-key', help='Google Custom Search API key')
    run_parser.add_argument('--google-cse-id', help='Google Custom Search Engine ID')
    run_parser.add_argument('--playwright', action='store_true', help='Enable Playwright for Strategy 4')

    # Consolidate
    consolidate_parser = subparsers.add_parser('consolidate',
        help='Merge recovery results into the main DB (only where main has unknown/no entry)')
    consolidate_parser.add_argument('--db', default='pm_recovery_results.db', help='Recovery database file path')
    consolidate_parser.add_argument('--main-db', default='pm_system_results.db', help='Main source of truth database')
    consolidate_parser.add_argument('--dry-run', action='store_true', help='Preview changes without writing')

    # Stats
    stats_parser = subparsers.add_parser('stats', help='Show database statistics')
    stats_parser.add_argument('--db', default='pm_system_results.db', help='Database file path')

    args = parser.parse_args()

    if args.command == 'run':
        strategies = None
        if args.strategies:
            strategies = [int(s.strip()) for s in args.strategies.split(',')]

        recovery = UnknownRecovery(
            db_path=args.db,
            main_db_path=args.main_db,
            google_api_key=args.google_api_key,
            google_cse_id=args.google_cse_id,
            use_playwright=args.playwright,
            dry_run=args.dry_run,
        )

        try:
            domains = None
            if args.domain:
                domains = [args.domain]

            recovery.run(
                domains=domains,
                strategies=strategies,
                limit=args.limit,
                workers=args.workers,
            )
        finally:
            recovery.close()

    elif args.command == 'consolidate':
        consolidate_recovery(
            recovery_db_path=args.db,
            main_db_path=args.main_db,
            dry_run=args.dry_run,
        )

    elif args.command == 'stats':
        db = ResultsDatabase(args.db)
        stats = db.get_stats()
        print(json.dumps(stats, indent=2))

        # Also show recovery-specific stats
        conn = sqlite3.connect(args.db)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT detection_method, COUNT(*)
            FROM results
            WHERE detection_method LIKE 'recovery:%'
            GROUP BY detection_method
            ORDER BY COUNT(*) DESC
        """)
        recovery_rows = cursor.fetchall()
        conn.close()

        if recovery_rows:
            print("\nRecovery detections:")
            for method, count in recovery_rows:
                print(f"  {method}: {count}")
        else:
            print("\nNo recovery detections yet.")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
