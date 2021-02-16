//import java.io.FileWriter;
//import java.io.IOException;

import mitre.cpe.CPEobject;
import mitre.cve.CVEobject;

public class Main {

    public static void putIntoDatabase(){

        // Putting all CPE objects from match feed file into database and actualizing them
        CPEobject.putIntoDatabase();

        // Putting all CVE objects and basic objects related to them into database and actualizing them
        CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2002.json"); // https://nvd.nist.gov/vuln/data-feeds
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2003.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2004.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2005.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2006.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2007.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2008.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2009.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2010.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2011.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2012.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2013.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2014.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2015.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2016.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2017.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2018.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2019.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2020.json");
        //CVEobject.putIntoDatabase("exclude/nvdcve-1.1-2021.json");
    }

    public static void main(String[] args) {
        System.out.println("Welcome to the VIP application");

        putIntoDatabase();
    }
}
