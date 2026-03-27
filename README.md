# nmap2CVE.sh

Bash script to parse an Nmap XML file, extract services with detected versions, and automatically query the NVD API for vulnerabilities (CVEs).
It displays services sorted by severity (CVSS) and grouped by IP address.

> ⚠️ Identified CVEs must be manually validated, as the service might not be correctly identified during the query on nvd.nist.gov, potentially leading to false positives or incorrect vulnerability assignments. ⚠️

## Use

```bash
./nmap2CVE.sh <file.xml>
```

## Output

```
1.2.3.4 
  - 3306 mysql MariaDB 11.8.6 
      1 CVEs — CVSS max: 8.5 
      https://nvd.nist.gov/vuln/search#/nvd/home?keyword=MariaDB%2011.8.6&resultType=records 

  - 8083 http lwIP 1.4.0 
      1 CVEs — CVSS max: 4.3
      https://nvd.nist.gov/vuln/search#/nvd/home?cpeFilterMode=cpe&cpeName=cpe:2.3:a:lwip_project:lwip:1.4.0:*:*:*:*:*:*:*&resultType=records
```
