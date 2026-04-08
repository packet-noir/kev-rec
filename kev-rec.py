import requests
import sys
from datetime import datetime, timedelta

def fetch_kev():
    data_source = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if data_source.status_code != 200:
        print(f'Error: {data_source.status_code}; Check URL.')
        sys.exit(1)
    return data_source.json()['vulnerabilities']

def cutoff_date(days_back):
    return (datetime.now() - timedelta(days=days_back)).date()

def filter_catalog(catalog, target_date):
    recent_cve = []
    for vuln in catalog:
        date = datetime.strptime(vuln['dateAdded'], '%Y-%m-%d').date()
        if date >= target_date:
            recent_cve.append(vuln)
    return recent_cve

def format_cve(cve):
    return f"{cve['cveID']} added on {cve['dateAdded']}\n{cve['vulnerabilityName']}\n"

def main():
    days_back = 30
    catalog = fetch_kev()
    target_date = cutoff_date(days_back)
    cve_list = filter_catalog(catalog, target_date)

    for item in cve_list:
        print(format_cve(item))

main()
