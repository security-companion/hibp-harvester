#!/bin/python

# Author security-companion
# This program uses the "haveibeenpwned API" in order to search multiple emails for data leaks via domain search

# Licensed under MIT (see LICENSE-file)

import configparser
import os.path
import sys

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

if __name__ == "__main__":
    config = read_config()
    print(config['DEFAULT']['API_KEY'])
