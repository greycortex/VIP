import com.google.gson.Gson;
import org.json.simple.*;

import java.io.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.Date;

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

    /**
     * Automatic ID
     */
    private final Long id;

    protected final String data_type;
    protected final String data_format;
    protected final String data_version;
    protected final String meta_data_id;
    protected final String meta_data_assigner;
    protected final ArrayList<CWEobject> problem_type_data;
    protected final ArrayList<ReferenceObject> references;
    protected final String description;
    protected final ArrayList<ArrayList<CPEobject>> cpe_matches;
    protected final ArrayList<boolean[]> vulnerables;
    protected final ArrayList<String> and_operators;
    protected final CVSS3object cvss_v3;
    protected final CVSS2object cvss_v2;
    protected final int cvss_v2_base_score;
    protected final int cvss_v3_base_score;
    protected final Date published_date;
    protected final Date last_modified_date;

    /**
     * Copies constructor
     *
     * @param data_format        data format parameter
     * @param data_version       data version parameter
     * @param meta_data_id       CVE meta data - ID parameter
     * @param meta_data_assigner CVE meta data - ASSIGNER parameter
     * @param problem_type_data  problem type data values (CWE objects)
     * @param references         reference objects - references
     * @param description        description
     * @param cpe_matches        CPE objects from nodes that contain them
     * @param vulnerables        vulnerability boolean values for each CPE object
     * @param and_operators      place of AND relation operators in nodes containing CPE objects
     * @param cvss_v3            CVSS V3 object with CVSS V3 parameters
     * @param cvss_v2            CVSS V2 object with CVSS V2 parameters
     * @param cvss_v2_base_score a CVSS V2 base score
     * @param cvss_v3_base_score a CVSS V3 base score
     * @param published_date     published date value
     * @param last_modified_date last modified date value
     */
    public CVEobject(String data_type, String data_format, String data_version, String meta_data_id, String meta_data_assigner,
                     ArrayList<CWEobject> problem_type_data, ArrayList<ReferenceObject> references, String description,
                     ArrayList<ArrayList<CPEobject>> cpe_matches, ArrayList<boolean[]> vulnerables,
                     ArrayList<String> and_operators, CVSS3object cvss_v3, CVSS2object cvss_v2, int cvss_v2_base_score,
                     int cvss_v3_base_score, Date published_date, Date last_modified_date) {

        this.id = null;
        this.data_type = data_type;
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
        this.cvss_v2_base_score = cvss_v2_base_score;
        this.cvss_v3_base_score = cvss_v3_base_score;
        this.published_date = published_date;
        this.last_modified_date = last_modified_date;

    }
}
