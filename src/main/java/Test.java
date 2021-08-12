import mitre.capec.CAPECattStepObj;
import mitre.capec.CAPECobject;
import mitre.capec.CAPECrelationObj;
import mitre.capec.CAPECskillObj;
import mitre.cpe.CPEcomplexObj;
import mitre.cpe.CPEnodeObject;
import mitre.cpe.CPEnodeToComplex;
import mitre.cpe.CPEobject;
import mitre.cve.CVEobject;
import mitre.cve.ReferenceObject;
import mitre.cvss.CVSS2object;
import mitre.cvss.CVSS3object;
import mitre.cwe.*;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.service.ServiceRegistry;

import java.util.List;
import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class Test {
    public static final String[] fileNames = {"exclude/nvdcve-1.1-2002.json", "exclude/nvdcve-1.1-2003.json", "exclude/nvdcve-1.1-2004.json",
                "exclude/nvdcve-1.1-2005.json", "exclude/nvdcve-1.1-2006.json", "exclude/nvdcve-1.1-2007.json", "exclude/nvdcve-1.1-2008.json",
                "exclude/nvdcve-1.1-2009.json", "exclude/nvdcve-1.1-2010.json", "exclude/nvdcve-1.1-2011.json", "exclude/nvdcve-1.1-2012.json",
                "exclude/nvdcve-1.1-2013.json", "exclude/nvdcve-1.1-2014.json", "exclude/nvdcve-1.1-2015.json", "exclude/nvdcve-1.1-2016.json",
                "exclude/nvdcve-1.1-2017.json", "exclude/nvdcve-1.1-2018.json", "exclude/nvdcve-1.1-2019.json", "exclude/nvdcve-1.1-2020.json",
                "exclude/nvdcve-1.1-2021.json"}; // "nvdcve-1.1-2002.json" -- "nvdcve-1.1-2021.json" - - - https://nvd.nist.gov/vuln/data-feeds
    public static final String cpe_file = "exclude/nvdcpematch-1.0.json"; // - - - https://nvd.nist.gov/vuln/data-feeds
    public static final String cwe_file = "exclude/cwec_v4.5.xml"; // - - - https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
    public static final String capec_file = "exclude/capec_latest.xml"; // - - - https://capec.mitre.org/data/xml/capec_latest.xml

    
    public static void putIntoDatabase(){

    }

    /**
     *
     * @param args
     * @return
     */
    public static void main(String[] args) {
        final String UPDATE = "u";
        
        Options options = new Options();
        options.addOption(UPDATE, false, "Update DB and export queries.");


        System.out.println("Welcome to the VIP application!");
        // parse commandline aguments and process each command
        try {
            CommandLineParser parser = new BasicParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption(UPDATE)) { // run update
                CVEobject.quickUpdate("exclude/nvdcve-1.1-modified.json");
            }

            // Putting all CVE, CWE, CAPEC and CPE objects and objects related to them into database and actualizing them
            //CVEobject.putIntoDatabase(cpe_file, fileNames, cwe_file, capec_file);
            
            // CWE, CAPEC 
            //TODO: 
            
            //CPEobject.feedReconstr(); // -- Reconstructs CPE match feed file by using objects from the database

            // exit with help
            else {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("java -jar VIP", options);
            }

                
        } catch (ParseException ex) {
            System.err.println("Parsing failed.  Reason: " + ex.getMessage());
        }
        
        // this is the end
    }
}
