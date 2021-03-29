# VIP
GREYCORTEX Vulnerability Intelligence Platform

### About
At the moment, this program can fully work with objects representing CPEs and CVEs.

It can parse CPEs from - [CPE match feed file](https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip) - and CVEs from - [CVE JSON data feeds](https://nvd.nist.gov/vuln/data-feeds)

VIP in its current state is also able to put these CPEs and CVEs into database including actualizations in quite short amounts of time.

It is also possible to completely (without content history) parse CWE objects - [XML file](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip)

and CAPEC objects - [XML file](https://capec.mitre.org/data/xml/capec_latest.xml) - thanks to the additional implemented methods.

### Current database schema

![Current database schema](https://github.com/greycortex/VIP/blob/master/doc/current_mitre_schema.png?raw=true)

Copyright (c) 2021 GreyCortex s.r.o.
