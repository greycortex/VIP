# VIP
GREYCORTEX Vulnerability Intelligence Platform

### About
At the moment, this program can work with objects representing CPEs and CVEs.

It can parse CPEs from [CPE match feed file](https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip)

It can parse CVEs from [CVE JSON data feeds](https://nvd.nist.gov/vuln/data-feeds)

It can also completely (without content history) parse CWE objects - [XML file](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip)

It can also completely (without content history) parse CAPEC objects - [XML file](https://capec.mitre.org/data/xml/capec_latest.xml)

It can also put these CPEs and CVEs into database including actualizations by working with first two of earlier mentioned up-to-date files.

### Current database schema

![Current database schema](https://github.com/greycortex/VIP/tree/master/doc/current_mitre_schema.jpg?raw=true)

Copyright (c) 2020 GreyCortex s.r.o.
