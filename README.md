# HTTP request analyzer for Apache sites

[Русский](README_RU.md) | [English](README.md)

Modern Python script for analyzing Apache configuration files to extract unique URLs for specific HTTP methods. Provides high performance, reliability, and flexible configuration.

## ✨ Features

### 🚀 Performance
- **Multithreaded processing** - parallel processing of log files
- **Efficient memory usage** - stream processing of large files
- **Compiled regular expressions** - optimized parsing
- **Smart validation** - prevention of processing invalid data

### 🛡️ Security and reliability
- **Safe file handling** - using pathlib
- **Error handling** - comprehensive error handling
- **Input validation** - checking domains and URLs
- **Protection against path traversal** - filtering malicious paths

### 📊 Advanced features
- **Configurable parameters** - configuration via command line arguments
- **Detailed logging** - monitoring of analysis process
- **Results statistics** - detailed information about found URLs
- **Unicode support** - correct handling of international domains

## 🔧 System requirements

- Python 3.7+
- Permission to read Apache configuration files
- Permission to read Apache log files
- Permission to write to output directory

## 📦 Installation

```bash
# Cloning the repository
git clone https://github.com/commeta/apache_url_analyzer
cd apache-url-analyzer
```

## 🚀 Usage

### Basic usage

```bash
# Run with default parameters
python3 apache_url_analyzer.py

# Run with superuser privileges (if required)
sudo python3 apache_url_analyzer.py
```

### Advanced options

```bash
# Configure paths and parameters
python3 apache_url_analyzer.py \
    --config-glob "/etc/apache2/sites-available/*.conf" \
    --output-dir "/var/log/apache2" \
    --methods POST PUT DELETE PATCH \
    --max-workers 8 \
    --log-level DEBUG

# Analyze only specific methods
python3 apache_url_analyzer.py --methods POST DELETE

# Increase number of threads for large servers
python3 apache_url_analyzer.py --max-workers 16
```

## 📋 Command line parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--config-glob` | Glob pattern for searching Apache configuration files | `/etc/apache2/sites-enabled/*/*.conf` |
| `--output-dir` | Directory for saving results | `/var/log/apache2` |
| `--methods` | HTTP methods for analysis | `POST DELETE PUT HEAD` |
| `--max-workers` | Maximum number of threads | `4` |
| `--log-level` | Logging level | `INFO` |

## 📁 Output file structure

The script creates separate files for each HTTP method:

```
/var/log/apache2/
├── sites_post.log     # URLs for POST requests
├── sites_delete.log   # URLs for DELETE requests
├── sites_put.log      # URLs for PUT requests
└── sites_head.log     # URLs for HEAD requests
```

### Output data format

```
example.com /api/users
example.com /api/posts
subdomain.example.com /admin/settings
another-site.com /webhook/github
```

## 🔍 Usage examples

### Security analysis

```bash
# Search for potentially dangerous POST requests
python3 apache_url_analyzer.py --methods POST
grep -i "admin\|upload\|exec\|cmd" /var/log/apache2/sites_post.log
```

### API monitoring

```bash
# Analyze API endpoints
python3 apache_url_analyzer.py --methods POST PUT DELETE PATCH
```

### Configuration debugging

```bash
# Detailed analysis with debug info
python3 apache_url_analyzer.py --log-level DEBUG
```

## Optimization

```bash
# For large servers
python3 apache_url_analyzer.py --max-workers 16

# For systems with limited memory
python3 apache_url_analyzer.py --max-workers 2
```
