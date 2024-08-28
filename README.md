# Apache HTTP Request Analyzer for Websites

This Python script analyzes Apache configuration files for websites to extract unique URLs for specific HTTP methods (POST, DELETE, PUT, HEAD). It generates separate files with “domain-URL” pairs for each method, allowing you to analyze traffic patterns and identify potential security issues.
Features:

- Apache Configuration File Analysis: The script scans Apache configuration files to locate CustomLog directives, which define access log files.
- URL Extraction: The script analyzes log files to extract URLs associated with specific HTTP methods.
- Domain Determination: The script determines the domain name for each URL based on the log file name.
- Duplicate Removal: The script removes duplicate URLs from the output files.
- Output Sorting: The script outputs sorted lists of unique URLs.

## Usage:

- Ensure Apache Log Files are Configured: Verify that your Apache websites are configured to use the CustomLog directive to record access logs.
- Install Python 3: The script requires Python 3.x.
- Run the Script: Run the script using the command python3 http_requests.py. This will create four output files:
- - /var/log/httpd/sites_post.log: Unique URLs for POST requests.
- - /var/log/httpd/sites_delete.log: Unique URLs for DELETE requests.
- - /var/log/httpd/sites_put.log: Unique URLs for PUT requests.
- - /var/log/httpd/sites_head.log: Unique URLs for HEAD requests.

## Notes:

- The script may require superuser privileges to access Apache configuration files.
- You can change the paths to the output files by modifying the corresponding variables in the script.

## Benefits:

- Security Analysis: Analyze potential malicious activity by identifying unusual URLs for specific HTTP methods.
- Traffic Analysis: Understand traffic patterns and identify popular website endpoints.
- Website Optimization: Analyze URL usage to improve website performance and resource allocation.

## Example Output:

/var/log/httpd/sites_post.log:
```
example.com /api/create_user
example.com /admin/update_settings
```

This script provides a valuable tool for analyzing Apache configuration files to obtain information about traffic and URLs used on your websites.
