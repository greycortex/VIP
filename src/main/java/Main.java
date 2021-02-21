//import java.io.FileWriter;
//import java.io.IOException;

import mitre.cpe.CPEobject;
import mitre.cve.CVEobject;

public class Main {

    public static void putIntoDatabase(){

        // Putting all CPE objects from match feed file into database and actualizing them
        CPEobject.putIntoDatabase();

        String[] fileNames = {"exclude/nvdcve-1.1-2002.json"}; // "nvdcve-1.1-2002.json" -- "nvdcve-1.1-2021.json" - - - https://nvd.nist.gov/vuln/data-feeds
        // Putting all CVE objects and basic objects related to them into database and actualizing them
        CVEobject.putIntoDatabase(fileNames);
    }

    public static void main(String[] args) {
        System.out.println("Welcome to the VIP application");
        putIntoDatabase();
    }
}
