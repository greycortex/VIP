# VIP
GREYCORTEX Vulnerability Intelligence Platform

## About
At the moment, this program can work with objects representing CPEs, CVEs, CWEs and CAPECs.

It can parse and save into database (including slow updates):

**CPE data from** - [CPE match feed file](https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip)

**CVE and CPE data from** - [CVE JSON data feeds](https://nvd.nist.gov/vuln/data-feeds)

**CWE data from** - [ZIP file containing XML file with all existing CWE weaknesses](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip)

**CAPEC data from** - [XML file containing all existing CAPEC attack patterns](https://capec.mitre.org/data/xml/capec_latest.xml)

There is a method which can successfully reconstruct CPE match feed file by using objects from the database, too.

## Current database schema

![Current database schema](https://github.com/greycortex/VIP/blob/master/doc/current_mitre_schema.png?raw=true)

Copyright (c) 2021 GreyCortex s.r.o.
