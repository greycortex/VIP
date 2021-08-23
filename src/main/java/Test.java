import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.util.Arrays;

public class Test {
    // CVEs from https://nvd.nist.gov/vuln/data-feeds
    public static final String[] cve_files = {"exclude/nvdcve-1.1-2002.json", "exclude/nvdcve-1.1-2003.json", "exclude/nvdcve-1.1-2004.json",
                "exclude/nvdcve-1.1-2005.json", "exclude/nvdcve-1.1-2006.json", "exclude/nvdcve-1.1-2007.json", "exclude/nvdcve-1.1-2008.json",
                "exclude/nvdcve-1.1-2009.json", "exclude/nvdcve-1.1-2010.json", "exclude/nvdcve-1.1-2011.json", "exclude/nvdcve-1.1-2012.json",
                "exclude/nvdcve-1.1-2013.json", "exclude/nvdcve-1.1-2014.json", "exclude/nvdcve-1.1-2015.json", "exclude/nvdcve-1.1-2016.json",
                "exclude/nvdcve-1.1-2017.json", "exclude/nvdcve-1.1-2018.json", "exclude/nvdcve-1.1-2019.json", "exclude/nvdcve-1.1-2020.json",
                "exclude/nvdcve-1.1-2021.json"};
    // CPEs from https://nvd.nist.gov/vuln/data-feeds
    public static final String cpe_file = "exclude/nvdcpematch-1.0.json";
    // CWEs from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
    public static final String cwe_file = "exclude/cwec_v4.5.xml";
    // CAPECs from https://capec.mitre.org/data/xml/capec_latest.xml
    public static final String capec_file = "exclude/capec_latest.xml";
    // CVEs from https://nvd.nist.gov/vuln/data-feeds
    public static final String update_cve_cpe_file = "exclude/nvdcve-1.1-modified.json";

    // Main method
    public static void main(String[] args) {
        final String UPDATE = "u";
        final String BASIC = "b";
        final String EXTENDED = "e";

        Options options = new Options();
        options.addOption(UPDATE, false, "Perform a quick update of the database. \nCVE file: '"+update_cve_cpe_file+"'");

        options.addOption(BASIC, false, "Create and fill database with data including CVE and CPE structures. " +
                                                         "\nCVE files: '"+ Arrays.toString(cve_files) +"' \nCPE file: '"+cpe_file+"'");

        options.addOption(EXTENDED, false, "Create and fill database with data including CVE, CPE, CWE and CAPEC structures. " +
                                                            "\nCVE files: '"+ Arrays.toString(cve_files) +"' \nCPE file: '"+cpe_file+"' " +
                                                            "\nCAPEC file: '"+capec_file+"' \nCWE file: '"+cwe_file+"'");

        System.out.println("Welcome to the VIP application!");
        // parse commandline arguments and process each command
        try {
            CommandLineParser parser = new BasicParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption(UPDATE)) { // run quick update
                NVDobject.quickUpdate(update_cve_cpe_file);
            }
            else if (cmd.hasOption(BASIC)) { // run basic database creation
                NVDobject.basicDatabase(cpe_file, cve_files);
            }
            else if (cmd.hasOption(EXTENDED)) { // run extended database creation
                NVDobject.extendedDatabase(cpe_file, cve_files, cwe_file, capec_file);
            }

            // Reconstructs CPE match feed file by using objects from the database
            // extended_mitre.cpe.CPEobject.feedReconstr();

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
