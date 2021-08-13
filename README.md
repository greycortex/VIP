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

## To compile this
UPDATE hibernate.cfg.xml and copy to src/main/resources/ to make this project.

## To run this
Usage: java -jar VIP
 -e   Extend the DB by CWEs and CAPEC.
 -i   Initiate DB and insert CPEs and CVEs.
 -u   Update DB and export queries.
CPE feed (https://nvd.nist.gov/vuln/data-feeds): exclude/nvdcpematch-1.0.json
CVE feeds (https://nvd.nist.gov/vuln/data-feeds): \[exclude/nvdcve-1.1-2002.json, exclude/nvdcve-1.1-2003.json, exclude/nvdcve-1.1-2004.json, exclude/nvdcve-1.1-2005.json, exclude/nvdcve-1.1-2006.json, exclude/nvdcve-1.1-2007.json, exclude/nvdcve-1.1-2008.json, exclude/nvdcve-1.1-2009.json, exclude/nvdcve-1.1-2010.json, exclude/nvdcve-1.1-2011.json, exclude/nvdcve-1.1-2012.json, exclude/nvdcve-1.1-2013.json, exclude/nvdcve-1.1-2014.json, exclude/nvdcve-1.1-2015.json, exclude/nvdcve-1.1-2016.json, exclude/nvdcve-1.1-2017.json, exclude/nvdcve-1.1-2018.json, exclude/nvdcve-1.1-2019.json, exclude/nvdcve-1.1-2020.json, exclude/nvdcve-1.1-2021.json\]

Copyright (c) 2021 GreyCortex s.r.o.
