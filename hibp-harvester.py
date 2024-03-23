#!/bin/python

# Author security-companion
# This program uses the "haveibeenpwned API" in order to search multiple emails for data leaks via domain search

# Licensed under MIT (see LICENSE-file)

import configparser
import os.path
import sys
import requests

def read_config():
    config_file_name = 'hibp-harvester.cfg'
    config_template_file_name = 'hibp-harvester_template.cfg'
    if os.path.exists(config_file_name):

        config = configparser.ConfigParser()
        config.read('hibp-harvester.cfg')
    else:
        print("Config file " + config_file_name + "does not exist, please create it by using the template file " + config_template_file_name)
        sys.exit(1)

    return config

def request_domains(config):
    url = "https://haveibeenpwned.com/api/v3/subscribeddomains"

    with requests.Session() as session:
        headers = {
            "hibp-api-key": config['DEFAULT']['API_KEY']
        }
        session.headers.update(headers)

        with session.get(url) as response:
            if not response.ok:
                if response.status_code == 401:
                    print("API key not valid")
                    sys.exit(1)
            subscribed_domains = response.json()
        return subscribed_domains

def request_breaches(subscribed_domains):
    for current_domain in subscribed_domains:
        print("harvesting domain: " + current_domain)

if __name__ == "__main__":
    config = read_config()
    #print(config['DEFAULT']['API_KEY'])

    subscribed_domains = request_domains(config)

    request_breaches(subscribed_domains)