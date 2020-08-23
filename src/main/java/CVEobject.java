import com.google.gson.Gson;
import org.json.simple.*;
import java.io.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

/**
 * This class represents a CVE object (cpe matches (CPE objects), CVSS V2 attributes, CVSS V3 attributes, CWE values, ...)
 *
 * --- Description of the class ---
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CVEobject {

    /**
     * DB connection
     */
    private static Connection db;

    protected final String data_format;
    protected final String data_version;
    protected final String meta_data_id;
    protected final String meta_data_assigner;
    protected final ArrayList<String> problem_type_data;
    protected final ArrayList<HashMap <String, String>> references;
    protected final String description;
    protected final ArrayList<ArrayList<CPEobject>> cpe_matches;
    protected final ArrayList<ArrayList<String>> vulnerables;
    protected final ArrayList<String> and_operators;
    protected final HashMap<String, String> cvss_v3;
    protected final HashMap<String, String> cvss_v2;
    protected final Date published_date;
    protected final Date last_modified_date;

    /**
     * Copies constructor
     *
     * @param data_format data format parameter
     * @param data_version data version parameter
     * @param meta_data_id CVE meta data - ID parameter
     * @param meta_data_assigner CVE meta data - ASSIGNER parameter
     * @param problem_type_data problem type data values (CWE)
     * @param references references for specific CVE object
     * @param description description of a specific CVE object
     * @param cpe_matches CPE objects from nodes which contain them
     * @param vulnerables vulnerability boolean values for each CPE object
     * @param and_operators place of AND relation operators in nodes containing CPE objects
     * @param cvss_v3 CVSS V3 parameters (key - name of the CVSS V3 parameter; value - value of that parameter)
     * @param cvss_v2 CVSS V2 parameters (key - name of the CVSS V2 parameter; value - value of that parameter)
     * @param published_date published date value
     * @param last_modified_date last modified date value
     */
    public CVEobject(String data_format, String data_version, String meta_data_id, String meta_data_assigner,
                     ArrayList<String> problem_type_data, ArrayList<HashMap<String, String>> references, String description,
                     ArrayList<ArrayList<CPEobject>> cpe_matches, ArrayList<ArrayList<String>> vulnerables,
                     ArrayList<String> and_operators, HashMap<String, String> cvss_v3, HashMap<String, String> cvss_v2,
                     Date published_date, Date last_modified_date){

        this.data_format = data_format;
        this.data_version = data_version;
        this.meta_data_id = meta_data_id;
        this.meta_data_assigner = meta_data_assigner;
        this.problem_type_data = problem_type_data;
        this.references = references;
        this.description = description;
        this.cpe_matches = cpe_matches;
        this.vulnerables = vulnerables;
        this.and_operators = and_operators;
        this.cvss_v3 = cvss_v3;
        this.cvss_v2 = cvss_v2;
        this.published_date = published_date;
        this.last_modified_date = last_modified_date;

    }
}
