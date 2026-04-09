import requests
import sys
from datetime import datetime, timedelta
import time

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

def format_cve(cve, score, severity):
    return f"{cve['cveID']} added on {cve['dateAdded']} - {severity} ({score})\n{cve['vulnerabilityName']}\n"

def fetch_cvss(cve_id):
    source = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
    if source.status_code != 200:
        return None
    
    data = source.json()

    vuln_list = data.get("vulnerabilities", [])
    if not vuln_list:
        return None
    
    metrics = vuln_list[0].get('cve', {}).get('metrics', {}).get('cvssMetricV31', [])
    if not metrics:
        return None
    
    return metrics[0].get('cvssData', {}).get('baseScore')

def cvss_severity(score):
    if score is None:
        return "Severity unavailable"
    elif score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    else:
        return "None"
    
def main():
    days_back = 30
    catalog = fetch_kev()
    target_date = cutoff_date(days_back)
    cve_list = filter_catalog(catalog, target_date)

    for item in cve_list:
        score = fetch_cvss(item['cveID'])
        severity = cvss_severity(score)
        print(format_cve(item, score, severity))
        time.sleep(6)

main()
