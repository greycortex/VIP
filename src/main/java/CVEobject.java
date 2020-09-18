import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.Date;
import java.io.*;
import java.sql.*;

/**
 * This class represents a CVE object (cpe matches (CPE objects), CVSS V2 (base metric v2) attributes, CVSS V3 (base metric v2) attributes, CWE values, ...)
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
    protected final ArrayList<String> descriptions;
    protected final String cve_data_version;
    protected final ArrayList<CPEnodeObject> cpe_nodes;
    protected final CVSS2object cvss_v2;
    protected final CVSS3object cvss_v3;
    protected final double cvss_v2_base_score;
    protected final double cvss_v3_base_score;
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
     * @param descriptions       descriptions
     * @param cve_data_version   cve data version
     * @param cpe_nodes          nodes containing CPE objects, operators relating to them, vulnerable parameter etc...
     * @param cvss_v2            CVSS V2 object with base metric v2 parameters
     * @param cvss_v3            CVSS V3 object with base metric v3 parameters
     * @param cvss_v2_base_score a CVSS V2 base score
     * @param cvss_v3_base_score a CVSS V3 base score
     * @param published_date     published date value
     * @param last_modified_date last modified date value
     */
    public CVEobject(String data_type, String data_format, String data_version, String meta_data_id, String meta_data_assigner,
                     ArrayList<CWEobject> problem_type_data, ArrayList<ReferenceObject> references, ArrayList<String> descriptions,
                     String cve_data_version, ArrayList<CPEnodeObject> cpe_nodes, CVSS2object cvss_v2, CVSS3object cvss_v3, double cvss_v2_base_score,
                     double cvss_v3_base_score, Date published_date, Date last_modified_date) {

        this.id = null;
        this.data_type = data_type;
        this.data_format = data_format;
        this.data_version = data_version;
        this.meta_data_id = meta_data_id;
        this.meta_data_assigner = meta_data_assigner;
        this.problem_type_data = problem_type_data;
        this.references = references;
        this.descriptions = descriptions;
        this.cve_data_version = cve_data_version;
        this.cpe_nodes = cpe_nodes;
        this.cvss_v2 = cvss_v2;
        this.cvss_v3 = cvss_v3;
        this.cvss_v2_base_score = cvss_v2_base_score;
        this.cvss_v3_base_score = cvss_v3_base_score;
        this.published_date = published_date;
        this.last_modified_date = last_modified_date;
    }

    /**
     * This method's purpose is to create and return all CVE objects from .json file (input)
     *
     * @param fileName path to the .json file with cve objects
     * @return all created CVE objects
     */
    public static ArrayList<CVEobject> CVEjsonToObjects(String fileName) {

        // Empty ArrayList of CVE objects which will later on be filled and returned
        ArrayList<CVEobject> cve_objs = new ArrayList<>();

        // Parsing .json file from input
        JSONParser parser = new JSONParser();

        try (Reader reader = new FileReader(fileName)) {

            JSONObject jsonObject = (JSONObject) parser.parse(reader);

            /**
             * Getting to "CVE_Items" json array and iterating through him (array of CVE objects,
             * configurations (CPE objects, ...) and impact objects (base metric v2 and v3))
             */
            JSONArray cve_items = (JSONArray) jsonObject.get("CVE_Items");
            Iterator<JSONObject> iterator = cve_items.iterator();

            while (iterator.hasNext()) {

                // Getting CVE item object
                JSONObject cve_item = iterator.next();

                // Getting CVE json object
                JSONObject cve = (JSONObject) cve_item.get("cve");

                // Getting first attributes
                String data_type_final = (String) cve.get("data_type");       // data_type
                String data_format_final = (String) cve.get("data_format");   // data_format
                String data_version_final = (String) cve.get("data_version"); // data_version

                // Getting meta data attributes
                JSONObject meta_data = (JSONObject) cve.get("CVE_data_meta");
                String meta_data_id_final = (String) meta_data.get("ID");             // meta_data_id
                String meta_data_assigner_final = (String) meta_data.get("ASSIGNER"); // meta_data_assigner

                // Getting CWE objects
                JSONObject problemtype = (JSONObject) cve.get("problemtype");
                JSONArray problemtype_data = (JSONArray) problemtype.get("problemtype_data");
                Iterator<JSONObject> problem_iterator = problemtype_data.iterator();
                ArrayList<CWEobject> problem_type_data_final = new ArrayList<>(); // problem_type_data
                while (problem_iterator.hasNext()) {
                    JSONArray description = (JSONArray) problem_iterator.next().get("description");
                    Iterator<JSONObject> description_iterator = description.iterator();
                    while (description_iterator.hasNext()) {
                        String value = (String) description_iterator.next().get("value");
                        String[] splitcwe = value.split("-");
                        value = splitcwe[1];
                        problem_type_data_final.add(CWEobject.createCWEobj(value)); // create method from CWEobject class used
                    }
                }

                // Getting reference objects
                JSONObject references = (JSONObject) cve.get("references");
                JSONArray reference_data = (JSONArray) references.get("reference_data");
                Iterator<JSONObject> reference_iterator = reference_data.iterator();
                ArrayList<ReferenceObject> references_final = new ArrayList<>(); // references
                while (reference_iterator.hasNext()) {
                    JSONObject reference = reference_iterator.next();
                    String url = (String) reference.get("url");
                    String refsource = (String) reference.get("refsource");
                    String name = (String) reference.get("name");
                    JSONArray tags = (JSONArray) reference.get("tags");
                    Iterator<String> ref_tags_iterator = tags.iterator();
                    ArrayList<String> tags_final = new ArrayList<>();
                    while (ref_tags_iterator.hasNext()) {
                        tags_final.add(ref_tags_iterator.next());
                    }
                    references_final.add(new ReferenceObject(url, name, refsource, tags_final));
                }

                // Getting descriptions
                JSONObject decription_obj = (JSONObject) cve.get("description");
                JSONArray description_data = (JSONArray) decription_obj.get("description_data");
                Iterator<JSONObject> description_obj_iterator = description_data.iterator();
                ArrayList<String> descriptions_final = new ArrayList<>(); // descriptions
                while (description_obj_iterator.hasNext()) {
                    String description_value = (String) description_obj_iterator.next().get("value");
                    descriptions_final.add(description_value);
                }

                /**
                 * Getting cve_data_version attribute, CPE objects, vulnerable attributes of CPE objects and
                 * informations about operators that relate to specific groups of CPE objects
                 */
                JSONObject configurations = (JSONObject) cve_item.get("configurations");
                String cve_data_version_final = (String) configurations.get("CVE_data_version"); // cve_data_version

                JSONArray nodes = (JSONArray) configurations.get("nodes");
                Iterator<JSONObject> nodes_iterator = nodes.iterator();
                ArrayList<CPEnodeObject> cpe_nodes_final = new ArrayList<>(); // cpe_nodes

                while (nodes_iterator.hasNext()) {
                    ArrayList<ArrayList<CPEobject>> cpe_matches_part = new ArrayList<>(); // cpe matches - CPE node object
                    ArrayList<ArrayList<Boolean>> vulnerables_part = new ArrayList<>(); // vulnerables - CPE node object
                    ArrayList<ArrayList<String>> version_start_excludings_part = new ArrayList<>(); // version_start_excludings - CPE node object
                    ArrayList<ArrayList<String>> version_end_excludings_part = new ArrayList<>(); // version_end_excludings - CPE node object
                    ArrayList<ArrayList<String>> version_start_includings_part = new ArrayList<>(); // version_start_includings - CPE node object
                    ArrayList<ArrayList<String>> version_end_includings_part = new ArrayList<>(); // version_end_includings - CPE node object
                    ArrayList<String> operators_part = new ArrayList<>(); // operators - CPE node object

                    JSONObject node = nodes_iterator.next();
                    String first_op = (String) node.get("operator");

                    if(node.get("negate") == null) operators_part.add("N"+first_op) ;
                    else operators_part.add(first_op) ;

                    if (node.get("children") != null) { // More complex structure
                        JSONArray children = (JSONArray) node.get("children");
                        Iterator<JSONObject> children_iterator = children.iterator();

                        while (children_iterator.hasNext()) {
                            ArrayList<CPEobject> cpe_matches_part_part = new ArrayList<>();
                            ArrayList<Boolean> vulnerables_part_part = new ArrayList<>();
                            ArrayList<String> version_start_excludings_part_part = new ArrayList<>();
                            ArrayList<String> version_end_excludings_part_part = new ArrayList<>();
                            ArrayList<String> version_start_includings_part_part = new ArrayList<>();
                            ArrayList<String> version_end_includings_part_part = new ArrayList<>();
                            JSONObject child = children_iterator.next();
                            if (child.get("negate") == null) {
                                String child_oper = (String) child.get("operator");
                                operators_part.add(child_oper);
                            } else {
                                String child_oper = (String) child.get("operator");
                                operators_part.add("N" + child_oper);
                            }
                            JSONArray cpe_match = (JSONArray) child.get("cpe_match");
                            Iterator<JSONObject> cpe_iterator = cpe_match.iterator();
                            while (cpe_iterator.hasNext()) {
                                JSONObject cpe_match_specific = cpe_iterator.next();
                                String cpe23uri = (String) cpe_match_specific.get("cpe23Uri");
                                boolean vulnerable = (boolean) cpe_match_specific.get("vulnerable");
                                String version_start_excluding = (String) cpe_match_specific.get("versionStartExcluding");
                                String version_end_excluding = (String) cpe_match_specific.get("versionEndExcluding");
                                String version_start_including = (String) cpe_match_specific.get("versionStartIncluding");
                                String version_end_including = (String) cpe_match_specific.get("versionEndIncluding");
                                cpe_matches_part_part.add(CPEobject.cpeUriToObject(cpe23uri)); // create method from CPEobject class used
                                vulnerables_part_part.add(vulnerable);
                                version_start_excludings_part_part.add(version_start_excluding);
                                version_end_excludings_part_part.add(version_end_excluding);
                                version_start_includings_part_part.add(version_start_including);
                                version_end_includings_part_part.add(version_end_including);
                            }
                            cpe_matches_part.add(cpe_matches_part_part);
                            vulnerables_part.add(vulnerables_part_part);
                            version_start_excludings_part.add(version_start_excludings_part_part);
                            version_end_excludings_part.add(version_end_excludings_part_part);
                            version_start_includings_part.add(version_start_includings_part_part);
                            version_end_includings_part.add(version_end_includings_part_part);
                        }
                        cpe_nodes_final.add(new CPEnodeObject(cpe_matches_part, vulnerables_part, version_start_excludings_part,
                                version_end_excludings_part, version_start_includings_part, version_end_includings_part,
                                operators_part)); // CPE node object added
                    } else { // Less complex structure
                        JSONArray cpe_match = (JSONArray) node.get("cpe_match");
                        if (cpe_match == null) {
                            ArrayList<CPEobject> cpe_matches_part_part = new ArrayList<>();
                            ArrayList<Boolean> vulnerables_part_part = new ArrayList<>();
                            ArrayList<String> version_start_excludings_part_part = new ArrayList<>();
                            ArrayList<String> version_end_excludings_part_part = new ArrayList<>();
                            ArrayList<String> version_start_includings_part_part = new ArrayList<>();
                            ArrayList<String> version_end_includings_part_part = new ArrayList<>();
                            cpe_matches_part.add(cpe_matches_part_part);
                            vulnerables_part.add(vulnerables_part_part);
                            version_start_excludings_part.add(version_start_excludings_part_part);
                            version_end_excludings_part.add(version_end_excludings_part_part);
                            version_start_includings_part.add(version_start_includings_part_part);
                            version_end_includings_part.add(version_end_includings_part_part);
                        } else {
                            Iterator<JSONObject> cpe_iterator = cpe_match.iterator();
                            while (cpe_iterator.hasNext()) {
                                ArrayList<CPEobject> cpe_matches_part_part = new ArrayList<>();
                                ArrayList<Boolean> vulnerables_part_part = new ArrayList<>();
                                ArrayList<String> version_start_excludings_part_part = new ArrayList<>();
                                ArrayList<String> version_end_excludings_part_part = new ArrayList<>();
                                ArrayList<String> version_start_includings_part_part = new ArrayList<>();
                                ArrayList<String> version_end_includings_part_part = new ArrayList<>();
                                JSONObject cpe_match_specific = cpe_iterator.next();
                                String cpe23uri = (String) cpe_match_specific.get("cpe23Uri");
                                boolean vulnerable = (boolean) cpe_match_specific.get("vulnerable");
                                String version_start_excluding = (String) cpe_match_specific.get("versionStartExcluding");
                                String version_end_excluding = (String) cpe_match_specific.get("versionEndExcluding");
                                String version_start_including = (String) cpe_match_specific.get("versionStartIncluding");
                                String version_end_including = (String) cpe_match_specific.get("versionEndIncluding");
                                cpe_matches_part_part.add(CPEobject.cpeUriToObject(cpe23uri)); // create method from CPEobject class used
                                vulnerables_part_part.add(vulnerable);
                                version_start_excludings_part_part.add(version_start_excluding);
                                version_end_excludings_part_part.add(version_end_excluding);
                                version_start_includings_part_part.add(version_start_including);
                                version_end_includings_part_part.add(version_end_including);
                                cpe_matches_part.add(cpe_matches_part_part);
                                vulnerables_part.add(vulnerables_part_part);
                                version_start_excludings_part.add(version_start_excludings_part_part);
                                version_end_excludings_part.add(version_end_excludings_part_part);
                                version_start_includings_part.add(version_start_includings_part_part);
                                version_end_includings_part.add(version_end_includings_part_part);
                            }
                        }
                        cpe_nodes_final.add(new CPEnodeObject(cpe_matches_part, vulnerables_part, version_start_excludings_part,
                                version_end_excludings_part, version_start_includings_part, version_end_includings_part,
                                operators_part)); // CPE node object added
                    }
                }

                // Getting impact json object
                JSONObject impact = (JSONObject) cve_item.get("impact");

                // Getting CVSS v3 (base metric v3) object
                CVSS3object cvss_v3_final = null; // cvss_v3
                double base_score_v3_final = 0.0;  // base_score_v3
                if (impact.get("baseMetricV3") == null) ;
                else {
                    JSONObject base_metric_v3 = (JSONObject) impact.get("baseMetricV3");
                    JSONObject cvss_v3_obj = (JSONObject) base_metric_v3.get("cvssV3");
                    String version_v3 = (String) cvss_v3_obj.get("version");

                    String vector_string_v3 = (String) cvss_v3_obj.get("vectorString");
                    String[] vector_string_v3_splitstr = vector_string_v3.split("/");

                    String attack_vector_v3 = null;
                    String attack_complexity_v3 = null;
                    String privileges_required_v3 = null;
                    String user_interaction_v3 = null;
                    String scope_v3 = null;
                    String confidentiality_impact_v3 = null;
                    String integrity_impact_v3 = null;
                    String availability_impact_v3 = null;

                    if (vector_string_v3_splitstr[1].equals("AV:N")) attack_vector_v3 = "NETWORK";
                    else if (vector_string_v3_splitstr[1].equals("AV:A")) attack_vector_v3 = "ADJACENT_NETWORK";
                    else if (vector_string_v3_splitstr[1].equals("AV:L")) attack_vector_v3 = "LOCAL";
                    else if (vector_string_v3_splitstr[1].equals("AV:P")) attack_vector_v3 = "PHYSICAL";

                    if (vector_string_v3_splitstr[2].equals("AC:L")) attack_complexity_v3 = "LOW";
                    else if (vector_string_v3_splitstr[2].equals("AC:H")) attack_complexity_v3 = "HIGH";

                    if (vector_string_v3_splitstr[3].equals("PR:N")) privileges_required_v3 = "NONE";
                    else if (vector_string_v3_splitstr[3].equals("PR:L")) privileges_required_v3 = "LOW";
                    else if (vector_string_v3_splitstr[3].equals("PR:H")) privileges_required_v3 = "HIGH";

                    if (vector_string_v3_splitstr[4].equals("UI:N")) user_interaction_v3 = "NONE";
                    else if (vector_string_v3_splitstr[4].equals("UI:R")) user_interaction_v3 = "REQUIRED";

                    if (vector_string_v3_splitstr[5].equals("S:U")) scope_v3 = "UNCHANGED";
                    else if (vector_string_v3_splitstr[5].equals("S:C")) scope_v3 = "CHANGED";

                    if (vector_string_v3_splitstr[6].equals("C:N")) confidentiality_impact_v3 = "NONE";
                    else if (vector_string_v3_splitstr[6].equals("C:L")) confidentiality_impact_v3 = "LOW";
                    else if (vector_string_v3_splitstr[6].equals("C:H")) confidentiality_impact_v3 = "HIGH";

                    if (vector_string_v3_splitstr[7].equals("I:N")) integrity_impact_v3 = "NONE";
                    else if (vector_string_v3_splitstr[7].equals("I:L")) integrity_impact_v3 = "LOW";
                    else if (vector_string_v3_splitstr[7].equals("I:H")) integrity_impact_v3 = "HIGH";

                    if (vector_string_v3_splitstr[8].equals("A:N")) availability_impact_v3 = "NONE";
                    else if (vector_string_v3_splitstr[8].equals("A:L")) availability_impact_v3 = "LOW";
                    else if (vector_string_v3_splitstr[8].equals("A:H")) availability_impact_v3 = "HIGH";

                    base_score_v3_final = (double) cvss_v3_obj.get("baseScore"); // base_score_v3
                    String base_severity_v3 = (String) cvss_v3_obj.get("baseSeverity");
                    double exploitability_score_v3 = (double) base_metric_v3.get("exploitabilityScore");
                    double impact_score_v3 = (double) base_metric_v3.get("impactScore");
                    cvss_v3_final = new CVSS3object(version_v3, vector_string_v3, attack_vector_v3, attack_complexity_v3,
                            privileges_required_v3, user_interaction_v3, scope_v3, confidentiality_impact_v3,
                            integrity_impact_v3, availability_impact_v3, base_score_v3_final, base_severity_v3,
                            exploitability_score_v3, impact_score_v3); // cvss_v3
                }

                // Getting CVSS v2 (base metric v2) object
                CVSS2object cvss_v2_final = null; // cvss_v3
                double base_score_v2_final = 0.0;  // base_score_v3
                if (impact.get("baseMetricV2") == null) ;
                else {
                    JSONObject base_metric_v2 = (JSONObject) impact.get("baseMetricV2");
                    JSONObject cvss_v2_obj = (JSONObject) base_metric_v2.get("cvssV2");
                    String version_v2 = (String) cvss_v2_obj.get("version");

                    String vector_string_v2 = (String) cvss_v2_obj.get("vectorString");
                    String[] vector_string_v2_splitstr = vector_string_v2.split("/");

                    String access_vector_v2 = null;
                    String access_complexity_v2 = null;
                    String authentication_v2 = null;
                    String confidentiality_impact_v2 = null;
                    String integrity_impact_v2 = null;
                    String availability_impact_v2 = null;

                    if (vector_string_v2_splitstr[0].equals("AV:L")) access_vector_v2 = "LOCAL";
                    else if (vector_string_v2_splitstr[0].equals("AV:A")) access_vector_v2 = "ADJACENT_NETWORK";
                    else if (vector_string_v2_splitstr[0].equals("AV:N")) access_vector_v2 = "NETWORK";

                    if (vector_string_v2_splitstr[1].equals("AC:H")) access_complexity_v2 = "HIGH";
                    else if (vector_string_v2_splitstr[1].equals("AC:M")) access_complexity_v2 = "MEDIUM";
                    else if (vector_string_v2_splitstr[1].equals("AC:L")) access_complexity_v2 = "LOW";

                    if (vector_string_v2_splitstr[2].equals("Au:M")) authentication_v2 = "MULTIPLE";
                    else if (vector_string_v2_splitstr[2].equals("Au:S")) authentication_v2 = "SINGLE";
                    else if (vector_string_v2_splitstr[2].equals("Au:N")) authentication_v2 = "NONE";

                    if (vector_string_v2_splitstr[3].equals("C:N")) confidentiality_impact_v2 = "NONE";
                    else if (vector_string_v2_splitstr[3].equals("C:P")) confidentiality_impact_v2 = "PARTIAL";
                    else if (vector_string_v2_splitstr[3].equals("C:C")) confidentiality_impact_v2 = "COMPLETE";

                    if (vector_string_v2_splitstr[4].equals("I:N")) integrity_impact_v2 = "NONE";
                    else if (vector_string_v2_splitstr[4].equals("I:P")) integrity_impact_v2 = "PARTIAL";
                    else if (vector_string_v2_splitstr[4].equals("I:C")) integrity_impact_v2 = "COMPLETE";

                    if (vector_string_v2_splitstr[5].equals("A:N")) availability_impact_v2 = "NONE";
                    else if (vector_string_v2_splitstr[5].equals("A:P")) availability_impact_v2 = "PARTIAL";
                    else if (vector_string_v2_splitstr[5].equals("A:C")) availability_impact_v2 = "COMPLETE";

                    base_score_v2_final = (double) cvss_v2_obj.get("baseScore"); // base_score_v2
                    String severity_v2 = (String) base_metric_v2.get("severity");
                    double exploitability_score_v2 = (double) base_metric_v2.get("exploitabilityScore");
                    double impact_score_v2 = (double) base_metric_v2.get("impactScore");
                    String ac_insuf_info_v2 = null;
                    String obtain_all_privilege_v2 = null;
                    String obtain_user_privilege_v2 = null;
                    String obtain_other_privilege_v2 = null;
                    String user_interaction_required_v2 = null;
                    if (base_metric_v2.get("acInsufInfo") == null) ;
                    else {
                        boolean ac_insuf_info_v2_boolean = (boolean) base_metric_v2.get("acInsufInfo");

                        if (ac_insuf_info_v2_boolean) ac_insuf_info_v2 = "true";
                        else ac_insuf_info_v2 = "false";
                    }
                    if (base_metric_v2.get("obtainAllPrivilege") == null) ;
                    else {
                        boolean obtain_all_privilege_v2_boolean = (boolean) base_metric_v2.get("obtainAllPrivilege");

                        if (obtain_all_privilege_v2_boolean) obtain_all_privilege_v2 = "true";
                        else obtain_all_privilege_v2 = "false";
                    }
                    if (base_metric_v2.get("obtainUserPrivilege") == null) ;
                    else {
                        boolean obtain_user_privilege_v2_boolean = (boolean) base_metric_v2.get("obtainUserPrivilege");

                        if (obtain_user_privilege_v2_boolean) obtain_user_privilege_v2 = "true";
                        else obtain_user_privilege_v2 = "false";
                    }
                    if (base_metric_v2.get("obtainOtherPrivilege") == null) ;
                    else {
                        boolean obtain_other_privilege_v2_boolean = (boolean) base_metric_v2.get("obtainOtherPrivilege");

                        if (obtain_other_privilege_v2_boolean) obtain_other_privilege_v2 = "true";
                        else obtain_other_privilege_v2 = "false";
                    }
                    if (base_metric_v2.get("userInteractionRequired") == null) ;
                    else {
                        boolean user_interaction_required_v2_boolean = (boolean) base_metric_v2.get("userInteractionRequired");

                        if (user_interaction_required_v2_boolean) user_interaction_required_v2 = "true";
                        else user_interaction_required_v2 = "false";
                    }

                    cvss_v2_final = new CVSS2object(version_v2, vector_string_v2, access_vector_v2, access_complexity_v2,
                            authentication_v2, confidentiality_impact_v2, integrity_impact_v2, availability_impact_v2,
                            base_score_v2_final, severity_v2, exploitability_score_v2, impact_score_v2, ac_insuf_info_v2,
                            obtain_all_privilege_v2, obtain_user_privilege_v2, obtain_other_privilege_v2,
                            user_interaction_required_v2); // cvss_v2
                }

                // Getting published date and last modified date attributes
                String published_date_final_string = (String) cve_item.get("publishedDate");
                String last_modified_date_final_string = (String) cve_item.get("lastModifiedDate");

                published_date_final_string = published_date_final_string.replace("T", "-");
                published_date_final_string = published_date_final_string.replace("Z", "");
                last_modified_date_final_string = last_modified_date_final_string.replace("T", "-");
                last_modified_date_final_string = last_modified_date_final_string.replace("Z", "");

                DateFormat dateformat = new SimpleDateFormat("yyyy-MM-dd-HH:mm");

                Date published_date_final = dateformat.parse(published_date_final_string); // published_date
                Date last_modified_date_final = dateformat.parse(last_modified_date_final_string); // last_modified_date

                // Creating CVE object and adding it into the returning arraylist
                cve_objs.add(new CVEobject(data_type_final, data_format_final, data_version_final, meta_data_id_final,
                        meta_data_assigner_final, problem_type_data_final, references_final, descriptions_final,
                        cve_data_version_final, cpe_nodes_final, cvss_v2_final, cvss_v3_final, base_score_v2_final,
                        base_score_v3_final, published_date_final, last_modified_date_final));
            }
        } catch (IOException | ParseException | java.text.ParseException ex) {
            ex.printStackTrace();
        }

        // Returning all created CVE objects
        return cve_objs;
    }

    @Override
    public String toString() {
        return "CVEobject{" +
                "id=" + id +
                ", data_type='" + data_type + '\'' +
                ", data_format='" + data_format + '\'' +
                ", data_version='" + data_version + '\'' +
                ", meta_data_id='" + meta_data_id + '\'' +
                ", meta_data_assigner='" + meta_data_assigner + '\'' +
                ", problem_type_data=" + problem_type_data +
                ", references=" + references +
                ", descriptions=" + descriptions +
                ", cve_data_version='" + cve_data_version + '\'' +
                ", cpe_nodes=" + cpe_nodes +
                ", cvss_v2=" + cvss_v2 +
                ", cvss_v3=" + cvss_v3 +
                ", cvss_v2_base_score=" + cvss_v2_base_score +
                ", cvss_v3_base_score=" + cvss_v3_base_score +
                ", published_date=" + published_date +
                ", last_modified_date=" + last_modified_date +
                '}';
    }
}
