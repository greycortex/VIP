//import java.io.FileWriter;
//import java.io.IOException;

import mitre.cve.CVEobject;

public class Main {

    public static void putIntoDatabase(){

        String[] fileNames = {"exclude/nvdcve-1.1-2002.json", "exclude/nvdcve-1.1-2003.json", "exclude/nvdcve-1.1-2004.json",
                "exclude/nvdcve-1.1-2005.json", "exclude/nvdcve-1.1-2006.json", "exclude/nvdcve-1.1-2007.json", "exclude/nvdcve-1.1-2008.json",
                "exclude/nvdcve-1.1-2009.json", "exclude/nvdcve-1.1-2010.json", "exclude/nvdcve-1.1-2011.json", "exclude/nvdcve-1.1-2012.json",
                "exclude/nvdcve-1.1-2013.json", "exclude/nvdcve-1.1-2014.json", "exclude/nvdcve-1.1-2015.json", "exclude/nvdcve-1.1-2016.json",
                "exclude/nvdcve-1.1-2017.json", "exclude/nvdcve-1.1-2018.json", "exclude/nvdcve-1.1-2019.json", "exclude/nvdcve-1.1-2020.json",
                "exclude/nvdcve-1.1-2021.json", }; // "nvdcve-1.1-2002.json" -- "nvdcve-1.1-2021.json" - - - https://nvd.nist.gov/vuln/data-feeds
        // Putting all CVE objects and basic objects related to them into database and actualizing them, Putting all CPE basic objects into database
        CVEobject.putIntoDatabase(fileNames);
    }

    public static void main(String[] args) {
        System.out.println("Welcome to the VIP application");
        putIntoDatabase();
    }
}
