#!/usr/bin/env python3
"""
Enhanced HTTP request analyzer for Apache sites

Analyzes Apache configuration files to extract unique URLs
for specified HTTP methods with improved error handling and performance.
"""

import os
import re
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import sys
from urllib.parse import urlparse, unquote


@dataclass
class Config:
    """Configuration for the analyzer"""
    apache_config_glob: str = "/etc/apache2/sites-enabled/*/*.conf"
    output_dir: str = "/var/log/apache2"
    http_methods: List[str] = None
    max_workers: int = 4
    log_level: str = "INFO"
    
    def __post_init__(self):
        if self.http_methods is None:
            self.http_methods = ["POST", "DELETE", "PUT", "HEAD"]


class ApacheLogAnalyzer:
    """Class for analyzing Apache logs"""
    
    def __init__(self, config: Config):
        self.config = config
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Compile regular expressions for better performance
        self.customlog_pattern = re.compile(r'CustomLog\s+([^\s]+)')
        self.log_line_pattern = re.compile(
            r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+([^\s"]+)[^"]*"\s+(\d+)\s+(\d+|-)'
        )
        
    def setup_logging(self):
        """Set up logging"""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('/var/log/apache_analyzer.log', mode='a')
            ]
        )
    
    def find_log_files(self) -> List[Path]:
        """Find all log files from Apache configuration files"""
        log_files = set()
        
        try:
            # Use pathlib for safe file searching
            config_files = list(Path("/").glob(self.config.apache_config_glob.lstrip('/')))
            
            for config_file in config_files:
                if not config_file.is_file():
                    continue
                    
                try:
                    with open(config_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    # Search for CustomLog directives
                    matches = self.customlog_pattern.findall(content)
                    for match in matches:
                        log_path = Path(match.strip('"\''))
                        if log_path.is_file():
                            log_files.add(log_path)
                            
                except (IOError, UnicodeDecodeError) as e:
                    self.logger.warning(f"Cannot read configuration file {config_file}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error while searching for configuration files: {e}")
            
        self.logger.info(f"Found {len(log_files)} log files")
        return list(log_files)
    
    def extract_domain_from_log_path(self, log_path: Path) -> str:
        """Extracts domain from log file path"""
        filename = log_path.stem
        
        # Try to extract domain from various naming formats
        patterns = [
            r'^([^-]+)-access$',  # domain-access.log
            r'^([^_]+)_access$',  # domain_access.log
            r'^access-([^-]+)$',  # access-domain.log
            r'^([^.]+)\..*$',     # domain.something.log
            r'^([^-]+)',          # first part before dash
        ]
        
        for pattern in patterns:
            match = re.match(pattern, filename)
            if match:
                domain = match.group(1)
                if self.is_valid_domain(domain):
                    return domain
                    
        # If unable to extract domain, use filename
        return filename
    
    def is_valid_domain(self, domain: str) -> bool:
        """Checks if the string is a valid domain"""
        if not domain or len(domain) > 253:
            return False
            
        # Basic domain format check
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        )
        return bool(domain_pattern.match(domain))
    
    def parse_log_line(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Parses an Apache log line and returns (IP, method, URL)"""
        try:
            match = self.log_line_pattern.match(line.strip())
            if match:
                ip, timestamp, method, url, status, size = match.groups()
                
                # Clean URL from query parameters
                url = url.split('?')[0]
                
                # Decode URL
                try:
                    url = unquote(url)
                except Exception:
                    pass  # If unable to decode, leave as is
                
                return ip, method, url
                
        except Exception as e:
            self.logger.debug(f"Error parsing log line: {e}")
            
        return None
    
    def process_log_file(self, log_file: Path) -> Dict[str, Set[str]]:
        """Processes a single log file and returns URLs by method"""
        domain = self.extract_domain_from_log_path(log_file)
        method_urls = {method: set() for method in self.config.http_methods}
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num % 10000 == 0:  # Progress for large files
                        self.logger.debug(f"Processed {line_num} lines in {log_file}")
                    
                    parsed = self.parse_log_line(line)
                    if parsed:
                        ip, method, url = parsed
                        
                        if method in self.config.http_methods:
                            # Validate URL
                            if self.is_valid_url(url):
                                method_urls[method].add(f"{domain} {url}")
                                
        except (IOError, UnicodeDecodeError) as e:
            self.logger.error(f"Error reading log file {log_file}: {e}")
            
        return method_urls
    
    def is_valid_url(self, url: str) -> bool:
        """Checks URL validity"""
        if not url or len(url) > 2048:  # Max URL length
            return False
            
        # Check that URL starts with /
        if not url.startswith('/'):
            return False
            
        # Exclude obviously malicious or unwanted paths
        excluded_patterns = [
            r'\.\./',  # path traversal
            r'//+',    # multiple slashes
            r'[\x00-\x1F\x7F]',  # control characters
        ]
        
        for pattern in excluded_patterns:
            if re.search(pattern, url):
                return False
                
        return True
    
    def analyze_logs(self) -> Dict[str, Set[str]]:
        """Analyzes all log files and returns unique URLs"""
        log_files = self.find_log_files()
        
        if not log_files:
            self.logger.warning("No log files found for analysis")
            return {method: set() for method in self.config.http_methods}
        
        # Combine results by method
        combined_results = {method: set() for method in self.config.http_methods}
        
        # Use multithreading to process files
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_file = {
                executor.submit(self.process_log_file, log_file): log_file 
                for log_file in log_files
            }
            
            for future in as_completed(future_to_file):
                log_file = future_to_file[future]
                try:
                    file_results = future.result()
                    
                    # Combine results
                    for method in self.config.http_methods:
                        combined_results[method].update(file_results[method])
                        
                    self.logger.info(f"Processed log file: {log_file}")
                    
                except Exception as e:
                    self.logger.error(f"Error processing file {log_file}: {e}")
        
        return combined_results
    
    def save_results(self, results: Dict[str, Set[str]]):
        """Saves results to files"""
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for method in self.config.http_methods:
            output_file = output_dir / f"sites_{method.lower()}.log"
            
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    # Sort by domain, then by URL
                    sorted_urls = sorted(results[method], key=lambda x: (x.split()[0], x.split()[1]))
                    
                    for url_entry in sorted_urls:
                        f.write(f"{url_entry}\n")
                
                self.logger.info(f"Saved {len(results[method])} unique URLs for {method} in {output_file}")
                
            except IOError as e:
                self.logger.error(f"Error saving results for {method}: {e}")
    
    def run(self):
        """Runs the analysis"""
        self.logger.info("Starting Apache log analysis...")
        
        try:
            results = self.analyze_logs()
            self.save_results(results)
            
            # Output statistics
            total_urls = sum(len(urls) for urls in results.values())
            self.logger.info(f"Analysis completed. Found {total_urls} unique URLs in total")
            
            for method in self.config.http_methods:
                count = len(results[method])
                self.logger.info(f"{method}: {count} unique URLs")
                
        except Exception as e:
            self.logger.error(f"Critical error during analysis: {e}")
            raise


def main():
    """Main function with command-line argument support"""
    parser = argparse.ArgumentParser(
        description='HTTP request analyzer for Apache sites'
    )
    parser.add_argument(
        '--config-glob', 
        default="/etc/apache2/sites-enabled/*/*.conf",
        help='Glob pattern to search for Apache configuration files'
    )
    parser.add_argument(
        '--output-dir', 
        default="/var/log/apache2",
        help='Directory to save results'
    )
    parser.add_argument(
        '--methods', 
        nargs='+', 
        default=['POST', 'DELETE', 'PUT', 'HEAD'],
        help='HTTP methods to analyze'
    )
    parser.add_argument(
        '--max-workers', 
        type=int, 
        default=4,
        help='Maximum number of threads for processing'
    )
    parser.add_argument(
        '--log-level', 
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level'
    )
    
    args = parser.parse_args()
    
    # Create configuration
    config = Config(
        apache_config_glob=args.config_glob,
        output_dir=args.output_dir,
        http_methods=args.methods,
        max_workers=args.max_workers,
        log_level=args.log_level
    )
    
    # Run analyzer
    analyzer = ApacheLogAnalyzer(config)
    analyzer.run()


if __name__ == "__main__":
    main()
