# VIP
GREYCORTEX Vulnerability Intelligence Platform

## About
At the moment, this program can work with objects representing CPEs, CVEs, CWEs and CAPECs.

It can parse and save into database (including slow updates):

**CPE data from** - [CPE match feed file](https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip)

**CVE and CPE data from** - [CVE JSON data feeds](https://nvd.nist.gov/vuln/data-feeds)

**CWE data from** - [ZIP file containing XML file with all existing CWE weaknesses](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip)

**CAPEC data from** - [XML file containing all existing CAPEC attack patterns](https://capec.mitre.org/data/xml/capec_latest.xml)

***It can also perform a quick update of CPE and CVE data thanks to "modified" file from*** - [CVE JSON data feeds](https://nvd.nist.gov/vuln/data-feeds)

There is a method which can successfully reconstruct CPE match feed file by using objects from the database, too.

### [JavaDoc documentation](https://htmlpreview.github.io/?https://github.com/greycortex/VIP/blob/master/doc/JavaDoc/index.html)

## To compile this project

**UPDATE hibernate.cfg.xml file and copy it to src/main/resources in this project.**

## Before working with database without Hibernate use

**For perfect database structure, update it by queries in the "update_schema_with_this.sql" file**

## To run this program

**Usage:** java -jar VIP
- -e &nbsp; &nbsp; &nbsp; Create and fill database with data including CVE, CPE, CWE and CAPEC structures
- -b &nbsp; &nbsp; &nbsp; Create and fill database with data including CVE and CPE structures
- -u &nbsp; &nbsp; &nbsp; Perform a quick update of the database (CPE and CVE data)

## Current database schemas

### Schema of basic structure of the database

![](https://github.com/greycortex/VIP/blob/master/doc/basic_mitre_schema.png?raw=true)

### Schema of extended structure of the database

![](https://github.com/greycortex/VIP/blob/master/doc/extended_mitre_schema.png?raw=true)

Copyright (c) 2021 GreyCortex s.r.o.
