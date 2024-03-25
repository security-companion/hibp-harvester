#!/bin/python

# Author security-companion
# This program uses the "haveibeenpwned API" in order to search multiple emails for data leaks via domain search

# Licensed under MIT (see LICENSE-file)

import configparser
import os.path
import sys
import requests

class Breach:
    def __init__(self, domain, alias, mail_address, breach_name):
        self.domain = domain
        self.alias = alias
        self.mail_address = mail_address
        self.breach_name = breach_name

class BreachLibrary:
    def __init__(self):
        self.breaches = []

    def number_of_breaches(self):
        return len(self.breaches)
    
    def add_breach(self, breach):
        self.breaches.append(breach)

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

def request_breaches(subscribed_domains, breachLibrary):
    for current_domain in subscribed_domains:
        #current_domain['PwnCountExcludingSpamListsAtLastSubscriptionRenewal']
        domain_name = current_domain['DomainName']
        print("harvesting domain: " + domain_name)
        if current_domain['PwnCount'] is None and current_domain['PwnCountExcludingSpamLists'] is None:
            print("domain has 0 pwns and 0 pwns exlcuding spam lists")
        else:
            print("domain has " + str(current_domain['PwnCount']) + " pwns and " + str(current_domain['PwnCountExcludingSpamLists']) + " pwns exlcuding spam lists")
            domain_breaches = request_breaches_for_domain(domain_name)
            for alias in domain_breaches:
                print("  breached alias: " + alias)
                breaches = domain_breaches[alias]
                breached_mail_address = f"{alias}@{domain_name}"
                #print(breached_mail_address)
                for current_breach in breaches:
                    #print(current_breach)
                    breach = Breach(domain_name, alias, breached_mail_address, current_breach)
                    breachLibrary.add_breach(breach)
        print(f"next subscription renewal: {current_domain['NextSubscriptionRenewal']}")
        print("-"*20)

def request_breaches_for_domain(domain):
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"

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
            domain_breaches = response.json()
        return domain_breaches    

if __name__ == "__main__":
    config = read_config()
    #print(config['DEFAULT']['API_KEY'])

    breachLibrary = BreachLibrary()

    subscribed_domains = request_domains(config)

    request_breaches(subscribed_domains, breachLibrary)

    print("-"*20)
    print(f"found {breachLibrary.number_of_breaches()} breaches in total")
    print("-"*20)