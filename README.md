# kev-rec

Retrieves catalog data from CISA's Known Exploited Vulnerability (KEV) database
and print CVEs added in the last N days.

By default, kev-rec.py lists CVEs added in the last 30 days. 
Configure this by modifying the value of the `days_back` variable
within main(). 

## Dependencies

- Python >= 3.10
- 'requests' third-party module

## Usage

```bash
python3 kev-rec.py
```

## Sample Output

```
CVE-2026-35616 added on 2026-04-06
Fortinet FortiClient EMS Improper Access Control Vulnerability

CVE-2026-3502 added on 2026-04-02
TrueConf Client Download of Code Without Integrity Check Vulnerability

CVE-2026-5281 added on 2026-04-01
Google Dawn Use-After-Free Vulnerability
```


