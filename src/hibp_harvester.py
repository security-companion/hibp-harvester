#!/bin/python

# Author security-companion
# This program uses the "haveibeenpwned API" in order to search multiple emails for data leaks via domain search

# Licensed under MIT (see LICENSE-file)

import configparser
import os.path
import sys
import time
import requests
import csv
import click


class Breach:
    def __init__(self, domain, alias, mail_address, breach_name, breach_date, added_date, modified_date):
        self.domain = domain
        self.alias = alias
        self.mail_address = mail_address
        self.breach_name = breach_name
        self.breach_date = breach_date
        self.added_date = added_date
        self.modified_date = modified_date

    def __iter__(self):
        return self


class BreachLibrary:
    def __init__(self):
        self.breaches = []

    def number_of_breaches(self):
        return len(self.breaches)

    def add_breach(self, breach):
        self.breaches.append(breach)

    def __iter__(self):
        return iter(self.breaches)


def read_config(api_key, wait_time):
    config_file_name = 'hibp-harvester.cfg'
    config_template_file_name = 'hibp-harvester_template.cfg'
    if os.path.exists(config_file_name):

        config = configparser.ConfigParser()
        config.read('hibp-harvester.cfg')
    else:
        print(f"Config file {config_file_name} does not exist, please create it by using \
              the template file {config_template_file_name}, using values from parameters")
        # sys.exit(1)
        config['DEFAULT']['API_KEY'] = api_key
        config['DEFAULT']['WAIT_TIME_SECONDS'] = wait_time

    return config


def make_request(config, url):
    with requests.Session() as session:
        headers = {
            "hibp-api-key": config['DEFAULT']['API_KEY'],
            "user-agent": "hibp-harvester"
        }
        session.headers.update(headers)

        wait_time_seconds = config['DEFAULT']['WAIT_TIME_SECONDS']
        print(f"wait {wait_time_seconds} seconds before next request")
        time.sleep(int(wait_time_seconds))

        with session.get(url) as response:
            if not response.ok:
                if response.status_code == 401:
                    print("API key not valid")
                    sys.exit(1)
                else:
                    print(f"response code: {response.status_code}")
                    print(f"response message: {response.message}")
                    sys.exit(1)
            response_json = response.json()
        return response_json


def request_all_breaches(config):
    url = "https://haveibeenpwned.com/api/v3/breaches"

    all_breaches = make_request(config, url)
    return all_breaches


def request_domains(config):
    url = "https://haveibeenpwned.com/api/v3/subscribeddomains"

    subscribed_domains = make_request(config, url)
    return subscribed_domains


def get_breach_details(current_breach, all_breaches):
    breach_date = "unknown"
    added_date = "unknown"
    modified_date = "unknown"

    for breach in all_breaches:
        if breach["Name"] == current_breach:
            breach_date = breach["BreachDate"]
            added_date = breach["AddedDate"]
            modified_date = breach["ModifiedDate"]
            break

    return {"breach_date": breach_date, "added_date": added_date, "modified_date": modified_date}


def request_breaches_for_subscribed_domains(config, subscribed_domains, breachLibrary, all_breaches):
    for current_domain in subscribed_domains:
        # current_domain['PwnCountExcludingSpamListsAtLastSubscriptionRenewal']
        domain_name = current_domain['DomainName']
        print("harvesting domain: " + domain_name)
        if current_domain['PwnCount'] is None and current_domain['PwnCountExcludingSpamLists'] is None:
            print("domain has 0 pwns and 0 pwns exlcuding spam lists")
        else:
            pwn_count_excluded = str(current_domain['PwnCountExcludingSpamLists'])
            print(f"domain has {str(current_domain['PwnCount'])} pwns and {pwn_count_excluded} pwns exlcuding spam lists")
            domain_breaches = request_breaches_for_domain(config, domain_name)

            for alias in domain_breaches:
                print("  breached alias: " + alias)
                breaches = domain_breaches[alias]
                breached_mail_address = f"{alias}@{domain_name}"
                # print(breached_mail_address)
                for current_breach in breaches:
                    # print(current_breach)
                    breach_details = get_breach_details(current_breach, all_breaches)
                    breach = Breach(domain_name, alias, breached_mail_address, current_breach, breach_details["breach_date"],
                                    breach_details["added_date"], breach_details["modified_date"])
                    breachLibrary.add_breach(breach)
        print(f"next subscription renewal: {current_domain['NextSubscriptionRenewal']}")
        print("-"*20)


def request_breaches_for_domain(config, domain):
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"

    domain_breaches = make_request(config, url)
    return domain_breaches


def save_breaches_to_file(breachLibrary):
    header_names = ["domain", "breached_alias", "breached_mail_address", "breach_name",
                    "breach_date", "added_date", "modified_date"]

    print("writing breaches to csv-file")

    with open("breaches.csv", "w", newline='') as f:
        write = csv.writer(f)

        write.writerow(header_names)
        # write.writerows(breachLibrary)
        for breach in breachLibrary:
            # print (f"{breach.domain},{breach.alias},{breach.mail_address},{breach.breach_name}")
            write.writerow([breach.domain, breach.alias, breach.mail_address, breach.breach_name,
                            breach.breach_date, breach.added_date, breach.modified_date])


@click.command()
@click.option(
    "--api_key",
    help="This specifies the api-key from haveibeenpwned",
)
@click.option(
    "--wait_time",
    help="The wait time in seconds between requests to the API",
)
def main(api_key, wait_time):
    config = read_config(api_key, wait_time)
    # print(config['DEFAULT']['API_KEY'])

    breachLibrary = BreachLibrary()

    all_breaches = request_all_breaches(config)

    subscribed_domains = request_domains(config)

    request_breaches_for_subscribed_domains(config, subscribed_domains, breachLibrary, all_breaches)

    save_breaches_to_file(breachLibrary)

    print("-"*20)
    print(f"found {breachLibrary.number_of_breaches()} breaches in {len(subscribed_domains)} domains")
    print("-"*20)


if __name__ == "__main__":
    main()
