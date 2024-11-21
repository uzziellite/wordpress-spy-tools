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
Then create a virtual environment for running your python script

    ```bash
    cd 
    python3 -m venv venv
    ```

## Usage

This script is subdivided into several parts depending on the information that is needed.

### Acquiring Domain Information

To acquire
