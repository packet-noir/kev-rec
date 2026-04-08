import requests
import sys
from datetime import datetime, timedelta


# Calculate Cutoff Date
DAYS_BACK = 30
target_date = (datetime.now() - timedelta(days=DAYS_BACK)).date()

# Fetch KEV Data
data_source = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
if data_source.status_code != 200:
    print(f'Error: {data_source.status_code}; Check URL.')
    sys.exit(1)
    
# Convert to JSON
kev_data = data_source.json()['vulnerabilities']

# Print KEVs Created On or After Cutoff Date
for vuln in kev_data:
    date = datetime.strptime(vuln['dateAdded'], '%Y-%m-%d').date()
    if date >= target_date:
        print(f"{vuln['cveID']} added on {date}\n{vuln['vulnerabilityName']}\n")
