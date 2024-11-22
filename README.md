# WordPress Security Tools

This is a collection of python scripts that are useful in pentesting a WordPress site to gather information about the target.
You can gather information about the following:

    - Server IP address
    - Domain Name Server Records
    - Open Ports and Services running on those ports
    - Whois Records of the target domain
    - SSL Certificate information
    - Server being used by the target
    - Website Headers analysis for further vulnerability assesment
    - Plugins available on the target site (Activated and Inactive)
    - Themes available on the target site (Activated and Inactive)

## Setup

To use this script, you have to first set it up. Begin by running the following:

```bash
    git clone https://github.com/uzziellite/wordpress-spy-tools.git
```

Then CD into this directory and create a virtual environment for running your python script

```bash
    python3 -m venv venv
    pip3 install -r requirements.txt
```

## Usage

This script is subdivided into several parts depending on the information that is needed.

Learn how to use this tool

```bash
python3 plugins.py -h
```

1. To acquire domain info

```bash
    python3 domain_scanner.py
```

2. To scan for plugins

```bash
    python3 plugins.py [url] [wordlist] --workers 10 --timeout 10 --no-verify-ssl --retries 3 --log-file [path_to_log_file]
```

Example

```bash
    python3 plugins.py https://example.com ./data/wp-plugins.fuzz.txt --workers 10 --timeout 10 --no-verify-ssl --retries 3 --log-file ./url_checker.log
```

This guide may still contain errors
