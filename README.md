[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)![Gitub Actions](https://github.com/security-companion/hibp-harvester/actions/workflows/python-app.yml/badge.svg)![Python](https://img.shields.io/badge/programming_language-python-blue)
# hibp-harvester
A python tool to harvest have-i-been-pwned via domain search

## Setup

* add your domains to the domain search dashboard on haveibeenpwend.com
* purchase a subscription to get an API key
* rename the template.cfg file to hibp-harvester.cfg
* run python install -r requirements.txt
* run python hibp-harvester.py
* open created csv-file eg. in Excel
* filter for single breach names so that you can inform users about eg. latest breach or filter for dates

Please do not run the harvester too often. 
haveibeenpwned informs you automatically about new breaches via mail for verified domains. If you get a mail about new breach then you can run the script once to get an updated csv-file which you can then filter

## Contributions
Contributions are always welcome, please open a pull request or an issue

## Author

hibp-harvester is developed and maintained by [Joachim Mammele](https://security-companion.net)