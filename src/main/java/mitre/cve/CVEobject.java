package mitre.cve;

import mitre.capec.CAPECattStepObj;
import mitre.capec.CAPECobject;
import mitre.capec.CAPECrelationObj;
import mitre.capec.CAPECskillObj;
import mitre.cpe.CPEnodeToComplex;
import mitre.cvss.CVSS3object;
import mitre.cvss.CVSS2object;
import mitre.cpe.CPEcomplexObj;
import mitre.cpe.CPEobject;
import mitre.cpe.CPEnodeObject;
import mitre.cwe.*;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.service.ServiceRegistry;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.persistence.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.io.*;
import java.util.Date;

/**
 * This class represents a CVE object (CPE matches (CPE objects), CVSS V2 (base metric v2) attributes, CVSS V3 (base metric v2) attributes, CWE, ...)
 * <p>
 * It can create and return all CVE objects from JSON file (input)
 * It can also put CVE, CWE and CAPEC objects and objects related to them into database including updates
 * <p>
 * It also can create CVE object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "cve")
@Table(name="cve", schema = "mitre")
public class CVEobject {

    public CVEobject() { } // default constructor

    @Id
    @Column(unique = true, name = "id")
    protected String meta_data_id;
    protected String data_type;
    protected String data_format;
    protected String data_version;
    protected String meta_data_assigner;
    @ManyToMany
    @CollectionTable(name = "cve_cwe", schema = "mitre")
    protected List<CWEobject> cwe;
    @OneToMany(mappedBy = "cve")
    protected List<ReferenceObject> references;
    @Column(length = 8191, name = "description")
    @CollectionTable(name = "cve_descriptions", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> descriptions;
    protected String cve_data_version;
    @OneToMany(mappedBy = "cve")
    protected List<CPEnodeObject> cpe_nodes;
    @OneToOne
    protected CVSS2object cvss_v2;
    @OneToOne
    protected CVSS3object cvss_v3;
    protected double cvss_v2_base_score;
    protected double cvss_v3_base_score;
    protected Date published_date;
    protected Date last_modified_date;

    /**
     * Copies constructor
     *
     * @param data_format        data format parameter
     * @param data_version       data version parameter
     * @param meta_data_id       CVE meta data - ID parameter
     * @param meta_data_assigner CVE meta data - ASSIGNER parameter
     * @param cwe                problem type data values (CWE objects)
     * @param references         reference objects - references
     * @param descriptions       descriptions
     * @param cve_data_version   CVE data version
     * @param cpe_nodes          nodes containing CPE objects, operators relating to them, vulnerable parameter etc...
     * @param cvss_v2            CVSS V2 object with base metric v2 parameters
     * @param cvss_v3            CVSS V3 object with base metric v3 parameters
     * @param cvss_v2_base_score a CVSS V2 base score
     * @param cvss_v3_base_score a CVSS V3 base score
     * @param published_date     published date value
     * @param last_modified_date last modified date value
     */
    public CVEobject(String data_type, String data_format, String data_version, String meta_data_id, String meta_data_assigner,
                     List<CWEobject> cwe, List<ReferenceObject> references, List<String> descriptions, String cve_data_version, List<CPEnodeObject> cpe_nodes,
                     CVSS2object cvss_v2, CVSS3object cvss_v3, double cvss_v2_base_score, double cvss_v3_base_score, Date published_date,
                     Date last_modified_date) {

        this.data_type = data_type;
        this.data_format = data_format;
        this.data_version = data_version;
        this.meta_data_id = meta_data_id;
        this.meta_data_assigner = meta_data_assigner;
        this.cwe = cwe;
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
     * This method's purpose is to create and return all CVE objects from JSON file (input)
     *
     * @param fileName path to the .json file with CVE objects
     * @param cwe_objects existing CWE objects for search of the relating ones
     * @param cwes_to_remove set of all CWE objects to remove from the list later on for optimalization
     * @return all created CVE objects
     */
    public static List<CVEobject> CVEjsonToObjects(String fileName, List<CWEobject> cwe_objects, Set<CWEobject> cwes_to_remove) { // https://nvd.nist.gov/vuln/data-feeds - fileName

        // Empty List of CVE objects which will later on be filled and returned
        List<CVEobject> cve_objs = new ArrayList<>();

        // Parsing JSON file from input
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
                List<CWEobject> cwe_objs_final = new ArrayList<>(); // problem_type_data - CWE objects
                while (problem_iterator.hasNext()) {
                    JSONArray description = (JSONArray) problem_iterator.next().get("description");
                    Iterator<JSONObject> description_iterator = description.iterator();
                    while (description_iterator.hasNext()) {
                        String value = (String) description_iterator.next().get("value");
                        String[] splitcwe = value.split("-");
                        value = splitcwe[1];
                        for (CWEobject cwe : cwe_objects){
                            if (cwe.getCode_id().equals(value)){
                                cwe_objs_final.add(cwe); // finds this CWE in existing list (from input)
                                cwes_to_remove.add(cwe); // Removing from original list
                            }
                        }
                    }
                }

                // Getting reference objects
                JSONObject references = (JSONObject) cve.get("references");
                JSONArray reference_data = (JSONArray) references.get("reference_data");
                Iterator<JSONObject> reference_iterator = reference_data.iterator();
                List<ReferenceObject> references_final = new ArrayList<>(); // references
                while (reference_iterator.hasNext()) {
                    JSONObject reference = reference_iterator.next();
                    String url = (String) reference.get("url");
                    String refsource = (String) reference.get("refsource");
                    String name = (String) reference.get("name");
                    JSONArray tags = (JSONArray) reference.get("tags");
                    Iterator<String> ref_tags_iterator = tags.iterator();
                    List<String> tags_final = new ArrayList<>();
                    while (ref_tags_iterator.hasNext()) {
                        tags_final.add(ref_tags_iterator.next());
                    }
                    references_final.add(new ReferenceObject(url, name, refsource, tags_final));
                }

                // Getting descriptions
                JSONObject decription_obj = (JSONObject) cve.get("description");
                JSONArray description_data = (JSONArray) decription_obj.get("description_data");
                Iterator<JSONObject> description_obj_iterator = description_data.iterator();
                List<String> descriptions_final = new ArrayList<>(); // descriptions
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
                List<CPEnodeObject> cpe_nodes_final = new ArrayList<>(); // cpe_nodes

                while (nodes_iterator.hasNext()) {
                    JSONObject node = nodes_iterator.next();
                    String first_op = (String) node.get("operator");

                    if (!(node.get("negate") == null)) first_op = "N" + first_op;

                    if (node.get("children") != null) { // More complex structure
                        CPEnodeObject parent_node_obj = new CPEnodeObject(null, first_op, null);
                        cpe_nodes_final.add(parent_node_obj); // new parent CPE node object added

                        JSONArray children = (JSONArray) node.get("children");
                        Iterator<JSONObject> children_iterator = children.iterator();

                        while (children_iterator.hasNext()) {
                            List<CPEcomplexObj> cpe_complex_objs = new ArrayList<>(); // complex CPE objects - CPE node object

                            JSONObject child = children_iterator.next();

                            String child_oper = (String) child.get("operator");
                            if (!(child.get("negate") == null)) child_oper = "N" + child_oper;

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
                                CPEobject cpe_normal_obj = CPEcomplexObj.cpeUriToObject(cpe23uri); // create method from CPEobject class used - normal CPE object
                                cpe_complex_objs.add(CPEcomplexObj.getInstanceFromCPE(cpe_normal_obj, vulnerable,
                                        version_start_excluding, version_end_excluding, version_start_including, version_end_including)); // CPEcompexObj class used - more complex CPE object

                            }
                            CPEnodeObject child_obj = new CPEnodeObject(cpe_complex_objs, child_oper, parent_node_obj); // creating child CPE node object (also creating relation with parent object)
                            cpe_nodes_final.add(child_obj); // child CPE node object added
                        }

                    } else { // Less complex structure
                        JSONArray cpe_match = (JSONArray) node.get("cpe_match");
                        List<CPEcomplexObj> cpe_complex_objs = new ArrayList<>(); // complex CPE objects - CPE node object

                        if (cpe_match != null) {
                            Iterator<JSONObject> cpe_iterator = cpe_match.iterator();
                            while (cpe_iterator.hasNext()) {
                                JSONObject cpe_match_specific = cpe_iterator.next();
                                String cpe23uri = (String) cpe_match_specific.get("cpe23Uri");
                                boolean vulnerable = (boolean) cpe_match_specific.get("vulnerable");
                                String version_start_excluding = (String) cpe_match_specific.get("versionStartExcluding");
                                String version_end_excluding = (String) cpe_match_specific.get("versionEndExcluding");
                                String version_start_including = (String) cpe_match_specific.get("versionStartIncluding");
                                String version_end_including = (String) cpe_match_specific.get("versionEndIncluding");
                                CPEobject cpe_normal_obj = CPEcomplexObj.cpeUriToObject(cpe23uri); // create method from CPEobject class used - normal CPE object
                                cpe_complex_objs.add(CPEcomplexObj.getInstanceFromCPE(cpe_normal_obj, vulnerable,
                                        version_start_excluding, version_end_excluding, version_start_including, version_end_including)); // CPEcompexObj class used - more complex CPE object
                            }
                        }
                        cpe_nodes_final.add(new CPEnodeObject(cpe_complex_objs, first_op, null)); // CPE node object added
                    }
                }

                // Getting impact JSON object
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
                        meta_data_assigner_final, cwe_objs_final, references_final, descriptions_final,
                        cve_data_version_final, cpe_nodes_final, cvss_v2_final, cvss_v3_final, base_score_v2_final,
                        base_score_v3_final, published_date_final, last_modified_date_final));
            }
        } catch (IOException | ParseException | java.text.ParseException ex) {
            ex.printStackTrace();
        }

        // Returning all created CVE objects
        return cve_objs;
    }

    /**
     * This method's purpose is to put all given CVE, CWE and CAPEC objects and related objects into database or to update them
     *
     * @param fileNames paths to .json files with CVE objects
     */
    public static void putIntoDatabase (String[] fileNames) {
        // Measuring, how long it will take to update the table in database
        long start_time = System.currentTimeMillis();

        List<CAPECobject> capec_objs = CAPECobject.CAPECfileToArrayList(); // Getting CAPEC objects from file
        List<CWEobject> cwe_objs = CWEobject.CWEfileToArraylist(capec_objs); // Getting CWE objects from file
        Set<CWEobject> cwes_to_remove = new LinkedHashSet<>(); // Set for removing connected CWE objects from original list for no data redundance in the database

        int refresh = 0; // Counting to ensure optimalization later on

        System.out.println("Actualization of objects in database started");

        // Creating connection, session factory and session
        Configuration con = new Configuration().configure().addAnnotatedClass(CVEobject.class).addAnnotatedClass(CPEobject.class)
                .addAnnotatedClass(CVSS2object.class).addAnnotatedClass(CVSS3object.class).addAnnotatedClass(CPEnodeObject.class)
                .addAnnotatedClass(ReferenceObject.class).addAnnotatedClass(CPEcomplexObj.class).addAnnotatedClass(CPEnodeToComplex.class)
                .addAnnotatedClass(CAPECattStepObj.class).addAnnotatedClass(CAPECobject.class).addAnnotatedClass(CAPECrelationObj.class)
                .addAnnotatedClass(CAPECskillObj.class).addAnnotatedClass(CWEalterTermObj.class).addAnnotatedClass(CWEapplPlatfObj.class)
                .addAnnotatedClass(CWEconseqObj.class).addAnnotatedClass(CWEdemExObj.class).addAnnotatedClass(CWEdetMethObj.class)
                .addAnnotatedClass(CWEexampCodeObj.class).addAnnotatedClass(CWEextRefRefObj.class).addAnnotatedClass(CWEintrModesObj.class)
                .addAnnotatedClass(CWEnoteObj.class).addAnnotatedClass(CWEobject.class).addAnnotatedClass(CWEobsExObj.class)
                .addAnnotatedClass(CWEpotMitObj.class).addAnnotatedClass(CWErelationObj.class).addAnnotatedClass(CWEtaxMapObj.class)
                .addAnnotatedClass(CWEweakOrdObj.class);
        ServiceRegistry reg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build();
        SessionFactory sf = con.buildSessionFactory(reg);
        Session session = sf.openSession();

        // If the cveobject table is empty, the method doesn't empty the database
        Query q = session.createQuery("from cve");
        q.setMaxResults(10);
        if (q.getResultList().isEmpty()) {
            System.out.println("Database table empty, emptying not included");
            // Closing session and session factory
            session.close();
            sf.close();
            // Putting CPE objects from CPE match feed file into database
            CPEobject.putIntoDatabase(); // file - https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip
            System.out.println("Actualization of CVE, CWE and CAPEC objects started");
            // Creating connection, session factory and session
            Configuration conn = new Configuration().configure().addAnnotatedClass(CVEobject.class).addAnnotatedClass(CPEobject.class)
                    .addAnnotatedClass(CVSS2object.class).addAnnotatedClass(CVSS3object.class).addAnnotatedClass(CPEnodeObject.class)
                    .addAnnotatedClass(ReferenceObject.class).addAnnotatedClass(CPEcomplexObj.class).addAnnotatedClass(CPEnodeToComplex.class)
                    .addAnnotatedClass(CAPECattStepObj.class).addAnnotatedClass(CAPECobject.class).addAnnotatedClass(CAPECrelationObj.class)
                    .addAnnotatedClass(CAPECskillObj.class).addAnnotatedClass(CWEalterTermObj.class).addAnnotatedClass(CWEapplPlatfObj.class)
                    .addAnnotatedClass(CWEconseqObj.class).addAnnotatedClass(CWEdemExObj.class).addAnnotatedClass(CWEdetMethObj.class)
                    .addAnnotatedClass(CWEexampCodeObj.class).addAnnotatedClass(CWEextRefRefObj.class).addAnnotatedClass(CWEintrModesObj.class)
                    .addAnnotatedClass(CWEnoteObj.class).addAnnotatedClass(CWEobject.class).addAnnotatedClass(CWEobsExObj.class)
                    .addAnnotatedClass(CWEpotMitObj.class).addAnnotatedClass(CWErelationObj.class).addAnnotatedClass(CWEtaxMapObj.class)
                    .addAnnotatedClass(CWEweakOrdObj.class);
            ServiceRegistry regg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build();
            SessionFactory sesf = conn.buildSessionFactory(regg);
            Session sessionc = sesf.openSession();
            // Going through each file given in input
            for (String fileName : fileNames) {
                // Taking objects returned by the CVEjsonToObjects() method
                List<CVEobject> cve_objs = CVEjsonToObjects(fileName, cwe_objs, cwes_to_remove);
                // Beginning transaction
                Transaction txv = sessionc.beginTransaction();
                // Putting CVE object and all the objects connected to CVE into database
                for (CVEobject obj : cve_objs) {
                    refresh++;
                    // Putting CVSS v2 object into database
                    if (!(obj.cvss_v2 == null)) sessionc.save(obj.cvss_v2);
                    // Putting CVSS v3 object into database
                    if (!(obj.cvss_v3 == null)) sessionc.save(obj.cvss_v3);
                    // Creating List for CWE removal from connections to prevent data redundance
                    List<CWEobject> cwe_to_remove = new ArrayList<>();
                    // Creating List for CWE connecting
                    List<CWEobject> cwes_to_add = new ArrayList<>();
                    // Putting related CWE and CAPEC objects into database
                    for (CWEobject cwe : obj.cwe) {
                        // If the CWE already exists in the database, only the connection between CWE and CVE will be made
                        if (sessionc.get(CWEobject.class, cwe.getCode_id()) != null) {
                            CWEobject cwe_to_add = (CWEobject) sessionc.get(CWEobject.class, cwe.getCode_id());
                            cwe_to_remove.add(cwe);
                            cwes_to_add.add(cwe_to_add);
                        } else {
                            // Creating List for CAPEC removal from connections to prevent data redundance
                            List<CAPECobject> capec_to_remove = new ArrayList<>();
                            // Creating List for CAPEC connecting
                            List<CAPECobject> capecs_to_add = new ArrayList<>();
                            // Putting related CAPEC objects into database
                            for (CAPECobject capec : cwe.getCapec()) {
                                // If the CAPEC already exists in the database, only the connection between CAPEC and CWE will be made
                                if (sessionc.get(CAPECobject.class, capec.getCapec_id()) != null) {
                                    CAPECobject capec_to_add = (CAPECobject) sessionc.get(CAPECobject.class, capec.getCapec_id());
                                    capec_to_remove.add(capec);
                                    capecs_to_add.add(capec_to_add);
                                } else {
                                    // Putting related CAPEC object into database
                                    sessionc.save(capec);
                                    // Putting CAPEC note objects into database
                                    for (CWEnoteObj note: capec.getNotes()) {
                                        note.setCapec(capec);
                                        sessionc.save(note);
                                    }
                                    // Putting CAPEC taxonomy mapping objects into database
                                    for (CWEtaxMapObj tax: capec.getTax_maps()) {
                                        tax.setCapec(capec);
                                        sessionc.save(tax);
                                    }
                                    // Putting CAPEC alternate term objects into database
                                    for (CWEalterTermObj alter: capec.getAlter_terms()) {
                                        alter.setCapec(capec);
                                        sessionc.save(alter);
                                    }
                                    // Putting external reference reference objects into database
                                    for (CWEextRefRefObj ext_ref_ref: capec.getExt_ref_refs()) {
                                        ext_ref_ref.setCapec(capec);
                                        sessionc.save(ext_ref_ref);
                                    }
                                    // Putting CAPEC consequence objects into database
                                    for (CWEconseqObj conseq: capec.getConsequences()) {
                                        conseq.setCapec(capec);
                                        sessionc.save(conseq);
                                    }
                                    // Putting CAPEC relation objects into database
                                    for (CAPECrelationObj relation: capec.getRelated_patterns()) {
                                        relation.setCapec(capec);
                                        sessionc.save(relation);
                                    }
                                    // Putting CAPEC attack step objects into database
                                    for (CAPECattStepObj att_step: capec.getAttack_steps()) {
                                        att_step.setCapec(capec);
                                        sessionc.save(att_step);
                                    }
                                    // Putting CAPEC skills required objects into database
                                    for (CAPECskillObj skill: capec.getSkills_required()) {
                                        skill.setCapec(capec);
                                        sessionc.save(skill);
                                    }
                                }
                            }
                            // CAPEC removal from connections to prevent data redundance
                            cwe.getCapec().removeAll(capec_to_remove);
                            // CAPEC connecting
                            cwe.getCapec().addAll(capecs_to_add);
                            // Putting CWE object into database
                            sessionc.save(cwe);
                            // Putting CWE relation objects into database
                            for (CWErelationObj rel: cwe.getRelations()) {
                                rel.setCwe(cwe);
                                sessionc.save(rel);
                            }
                            // Putting CWE applicable platform objects into database
                            for (CWEapplPlatfObj appl: cwe.getAppl_platform_objs()) {
                                appl.setCwe(cwe);
                                sessionc.save(appl);
                            }
                            // Putting CWE note objects into database
                            for (CWEnoteObj note: cwe.getNotes()) {
                                note.setCwe(cwe);
                                sessionc.save(note);
                            }
                            // Putting CWE introduction mode objects into database
                            for (CWEintrModesObj intr: cwe.getIntr_modes()) {
                                intr.setCwe(cwe);
                                sessionc.save(intr);
                            }
                            // Putting CWE consequence objects into database
                            for (CWEconseqObj conseq: cwe.getConsequences()) {
                                conseq.setCwe(cwe);
                                sessionc.save(conseq);
                            }
                            // Putting CWE alternate terms objects into database
                            for (CWEalterTermObj alter: cwe.getAlter_terms()) {
                                alter.setCwe(cwe);
                                sessionc.save(alter);
                            }
                            // Putting external reference reference objects into database
                            for (CWEextRefRefObj ext_ref_ref: cwe.getExt_ref_refs()) {
                                ext_ref_ref.setCwe(cwe);
                                sessionc.save(ext_ref_ref);
                            }
                            // Putting CWE taxonomy mapping objects into database
                            for (CWEtaxMapObj tax: cwe.getTax_maps()) {
                                tax.setCwe(cwe);
                                sessionc.save(tax);
                            }
                            // Putting CWE potential mitigation objects into database
                            for (CWEpotMitObj pot: cwe.getPot_mits()) {
                                pot.setCwe(cwe);
                                sessionc.save(pot);
                            }
                            // Putting CWE weakness ordinality objects into database
                            for (CWEweakOrdObj ord: cwe.getWeak_ords()) {
                                ord.setCwe(cwe);
                                sessionc.save(ord);
                            }
                            // Putting CWE demonstrative example objects into database
                            for (CWEdemExObj dem_ex: cwe.getDem_examples()) {
                                dem_ex.setCwe(cwe);
                                sessionc.save(dem_ex);
                                // Putting CWE CWE demonstrative example - example code objects into database
                                for (CWEexampCodeObj examp_code : dem_ex.getDem_ex_ex_codes()) {
                                    examp_code.setDem_ex(dem_ex);
                                    sessionc.save(examp_code);
                                }
                                // Putting CWE CWE demonstrative example - external reference reference objects into database
                                for (CWEextRefRefObj ext_ref_ref : dem_ex.getDem_ex_ext_ref_refs()) {
                                    ext_ref_ref.setDem_ex(dem_ex);
                                    sessionc.save(ext_ref_ref);
                                }
                            }
                            // Putting CWE observed example objects into database
                            for (CWEobsExObj obs_ex: cwe.getObs_examples()) {
                                obs_ex.setCwe(cwe);
                                sessionc.save(obs_ex);
                            }
                            // Putting CWE detection method objects into database
                            for (CWEdetMethObj det_met: cwe.getDet_meths()) {
                                det_met.setCwe(cwe);
                                sessionc.save(det_met);
                            }
                        }
                    }
                    // CWE removal from connections to prevent data redundance
                    obj.cwe.removeAll(cwe_to_remove);
                    // CWE connecting
                    obj.cwe.addAll(cwes_to_add);
                    // Putting CVE object into database
                    sessionc.save(obj);
                    // Putting CPE node objects into database
                    for (CPEnodeObject node_obj : obj.cpe_nodes) {
                        if (node_obj != null && node_obj.getComplex_cpe_objs() != null) {
                            for (CPEcomplexObj complex_cpe_obj : node_obj.getComplex_cpe_objs()) {
                                if (!(complex_cpe_obj == null)) {
                                    complex_cpe_obj.setCpe_objs(new ArrayList<>());
                                    Serializable cpe_spec_id = complex_cpe_obj.getCpe_id();
                                    CPEobject cpe_to_add = (CPEobject) sessionc.get(CPEobject.class, cpe_spec_id);
                                    // Connecting the right specific CPE object to the specific complex CPE object
                                    complex_cpe_obj.getCpe_objs().add(cpe_to_add);
                                    UUID uuid = UUID.randomUUID();
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "*" + uuid.toString()); // creating unique ID
                                    // Creating the relation between CVE, complex CPE and node object, adding also vulnerable attribute to it
                                    CPEnodeToComplex node_to_compl_cpe = new CPEnodeToComplex((obj.meta_data_id+"*"+complex_cpe_obj.getCpe_id()), complex_cpe_obj, node_obj, obj.meta_data_id, complex_cpe_obj.getVulnerable());
                                    // Putting CPE note to complex CPE object into database
                                    sessionc.save(node_to_compl_cpe);
                                    // Putting complex CPE object into database
                                    sessionc.save(complex_cpe_obj);
                                }
                            }
                            // Putting CPE node object into database
                            node_obj.setCve_obj(obj);
                            sessionc.save(node_obj);
                        } else if (node_obj != null) {
                            // Putting CPE node object into database
                            node_obj.setCve_obj(obj);
                            sessionc.save(node_obj);
                        }
                    }
                    for (ReferenceObject ref_obj : obj.references) {
                        // Putting CVE reference object into database
                        ref_obj.setCve_obj(obj);
                        sessionc.save(ref_obj);
                    }
                    // Ensuring optimalization
                    if (refresh % 250 == 0) {
                        txv.commit();
                        sessionc.close();
                        sessionc = sesf.openSession();
                        txv = sessionc.beginTransaction();
                    }
                }
                // Ending transaction
                if (txv.isActive()) txv.commit();
            }
            // Ending session
            if (sessionc.isOpen()) sessionc.close();

            // Removing connected CWE objects from original list for no data redundance in the database
            cwe_objs.removeAll(cwes_to_remove);

            // Opening session, beginning transaction
            sessionc = sesf.openSession();
            Transaction txv = sessionc.beginTransaction();

            // Putting the rest of CWE and CAPEC objects related to them into database
            for (CWEobject cwe : cwe_objs) {
                if (sessionc.get(CWEobject.class, cwe.getCode_id()) == null) {
                    // Creating List for CAPEC removal from connections to prevent data redundance
                    List<CAPECobject> capec_to_remove = new ArrayList<>();
                    // Creating List for CAPEC connecting
                    List<CAPECobject> capecs_to_add = new ArrayList<>();
                    // Putting related CAPEC objects into database
                    for (CAPECobject capec : cwe.getCapec()) {
                        // If the CAPEC already exists in the database, only the connection between CAPEC and CWE will be made
                        if (sessionc.get(CAPECobject.class, capec.getCapec_id()) != null) {
                            CAPECobject capec_to_add = (CAPECobject) sessionc.get(CAPECobject.class, capec.getCapec_id());
                            capec_to_remove.add(capec);
                            capecs_to_add.add(capec_to_add);
                        } else {
                            // Putting related CAPEC object into database
                            sessionc.save(capec);
                            // Putting CAPEC note objects into database
                            for (CWEnoteObj note: capec.getNotes()) {
                                note.setCapec(capec);
                                sessionc.save(note);
                            }
                            // Putting CAPEC taxonomy mapping objects into database
                            for (CWEtaxMapObj tax: capec.getTax_maps()) {
                                tax.setCapec(capec);
                                sessionc.save(tax);
                            }
                            // Putting CAPEC alternate term objects into database
                            for (CWEalterTermObj alter: capec.getAlter_terms()) {
                                alter.setCapec(capec);
                                sessionc.save(alter);
                            }
                            // Putting external reference reference objects into database
                            for (CWEextRefRefObj ext_ref_ref: capec.getExt_ref_refs()) {
                                ext_ref_ref.setCapec(capec);
                                sessionc.save(ext_ref_ref);
                            }
                            // Putting CAPEC consequence objects into database
                            for (CWEconseqObj conseq: capec.getConsequences()) {
                                conseq.setCapec(capec);
                                sessionc.save(conseq);
                            }
                            // Putting CAPEC relation objects into database
                            for (CAPECrelationObj relation: capec.getRelated_patterns()) {
                                relation.setCapec(capec);
                                sessionc.save(relation);
                            }
                            // Putting CAPEC attack step objects into database
                            for (CAPECattStepObj att_step: capec.getAttack_steps()) {
                                att_step.setCapec(capec);
                                sessionc.save(att_step);
                            }
                            // Putting CAPEC skills required objects into database
                            for (CAPECskillObj skill: capec.getSkills_required()) {
                                skill.setCapec(capec);
                                sessionc.save(skill);
                            }
                        }
                    }
                    // CAPEC removal from connections to prevent data redundance
                    cwe.getCapec().removeAll(capec_to_remove);
                    // CAPEC connecting
                    cwe.getCapec().addAll(capecs_to_add);
                    // Putting CWE object into database
                    sessionc.save(cwe);
                    // Putting CWE relation objects into database
                    for (CWErelationObj rel: cwe.getRelations()) {
                        rel.setCwe(cwe);
                        sessionc.save(rel);
                    }
                    // Putting CWE applicable platform objects into database
                    for (CWEapplPlatfObj appl: cwe.getAppl_platform_objs()) {
                        appl.setCwe(cwe);
                        sessionc.save(appl);
                    }
                    // Putting CWE note objects into database
                    for (CWEnoteObj note: cwe.getNotes()) {
                        note.setCwe(cwe);
                        sessionc.save(note);
                    }
                    // Putting CWE introduction mode objects into database
                    for (CWEintrModesObj intr: cwe.getIntr_modes()) {
                        intr.setCwe(cwe);
                        sessionc.save(intr);
                    }
                    // Putting CWE consequence objects into database
                    for (CWEconseqObj conseq: cwe.getConsequences()) {
                        conseq.setCwe(cwe);
                        sessionc.save(conseq);
                    }
                    // Putting CWE alternate terms objects into database
                    for (CWEalterTermObj alter: cwe.getAlter_terms()) {
                        alter.setCwe(cwe);
                        sessionc.save(alter);
                    }
                    // Putting external reference reference objects into database
                    for (CWEextRefRefObj ext_ref_ref: cwe.getExt_ref_refs()) {
                        ext_ref_ref.setCwe(cwe);
                        sessionc.save(ext_ref_ref);
                    }
                    // Putting CWE taxonomy mapping objects into database
                    for (CWEtaxMapObj tax: cwe.getTax_maps()) {
                        tax.setCwe(cwe);
                        sessionc.save(tax);
                    }
                    // Putting CWE potential mitigation objects into database
                    for (CWEpotMitObj pot: cwe.getPot_mits()) {
                        pot.setCwe(cwe);
                        sessionc.save(pot);
                    }
                    // Putting CWE weakness ordinality objects into database
                    for (CWEweakOrdObj ord: cwe.getWeak_ords()) {
                        ord.setCwe(cwe);
                        sessionc.save(ord);
                    }
                    // Putting CWE demonstrative example objects into database
                    for (CWEdemExObj dem_ex: cwe.getDem_examples()) {
                        dem_ex.setCwe(cwe);
                        sessionc.save(dem_ex);
                        // Putting CWE CWE demonstrative example - example code objects into database
                        for (CWEexampCodeObj examp_code : dem_ex.getDem_ex_ex_codes()) {
                            examp_code.setDem_ex(dem_ex);
                            sessionc.save(examp_code);
                        }
                        // Putting CWE CWE demonstrative example - external reference reference objects into database
                        for (CWEextRefRefObj ext_ref_ref : dem_ex.getDem_ex_ext_ref_refs()) {
                            ext_ref_ref.setDem_ex(dem_ex);
                            sessionc.save(ext_ref_ref);
                        }
                    }
                    // Putting CWE observed example objects into database
                    for (CWEobsExObj obs_ex: cwe.getObs_examples()) {
                        obs_ex.setCwe(cwe);
                        sessionc.save(obs_ex);
                    }
                    // Putting CWE detection method objects into database
                    for (CWEdetMethObj det_met: cwe.getDet_meths()) {
                        det_met.setCwe(cwe);
                        sessionc.save(det_met);
                    }
                }
            }

            // Committing transaction
            txv.commit();
            // Beginning transaction
            txv = sessionc.beginTransaction();

            // Putting the rest of CAPEC objects into database
            for (CAPECobject capec : capec_objs) {
                if (sessionc.get(CAPECobject.class, capec.getCapec_id()) == null) {
                    // Putting related CAPEC object into database
                    sessionc.save(capec);
                    // Putting CAPEC note objects into database
                    for (CWEnoteObj note: capec.getNotes()) {
                        note.setCapec(capec);
                        sessionc.save(note);
                    }
                    // Putting CAPEC taxonomy mapping objects into database
                    for (CWEtaxMapObj tax: capec.getTax_maps()) {
                        tax.setCapec(capec);
                        sessionc.save(tax);
                    }
                    // Putting CAPEC alternate term objects into database
                    for (CWEalterTermObj alter: capec.getAlter_terms()) {
                        alter.setCapec(capec);
                        sessionc.save(alter);
                    }
                    // Putting external reference reference objects into database
                    for (CWEextRefRefObj ext_ref_ref: capec.getExt_ref_refs()) {
                        ext_ref_ref.setCapec(capec);
                        sessionc.save(ext_ref_ref);
                    }
                    // Putting CAPEC consequence objects into database
                    for (CWEconseqObj conseq: capec.getConsequences()) {
                        conseq.setCapec(capec);
                        sessionc.save(conseq);
                    }
                    // Putting CAPEC relation objects into database
                    for (CAPECrelationObj relation: capec.getRelated_patterns()) {
                        relation.setCapec(capec);
                        sessionc.save(relation);
                    }
                    // Putting CAPEC attack step objects into database
                    for (CAPECattStepObj att_step: capec.getAttack_steps()) {
                        att_step.setCapec(capec);
                        sessionc.save(att_step);
                    }
                    // Putting CAPEC skills required objects into database
                    for (CAPECskillObj skill: capec.getSkills_required()) {
                        skill.setCapec(capec);
                        sessionc.save(skill);
                    }
                }
            }

            // Committing transaction
            txv.commit();
            // Ending session
            if (sessionc.isOpen()) sessionc.close();
            System.out.println("Actualization of CVE, CWE and CAPEC objects done");
        }

        // If the cveobject table isn't empty, the method does empty the database
        else {
            System.out.println("Database table not empty, emptying database");
            // Emptying database
            session.beginTransaction();
            session.createSQLQuery("DROP TABLE IF EXISTS mitre.affected_resources CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.alternate_term CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.applicable_platform CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.attack_step CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.bg_details CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.body_texts CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.capec CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.capec_relation CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.consequence CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.consequence_notes CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cpe CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cpe_compl_cpe CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cve CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cve_cwe CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cvss2 CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cvss3 CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_capec CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_relation CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.demonstrative_examp CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.descriptions CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.detection_method CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.example_code CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.examples CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.exclude_ids CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.external_ref_ref CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.functional_areas CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.impacts CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.indicators CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.introduction CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.likelihoods CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.mitigations CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.node CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.node_compl_cpe CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.note CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.observed_example CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.phases CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.potential_mitigation CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.prerequisites CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.ref_tags CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.reference CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.resources CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.scopes CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.skill CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.taxonomy_mapping CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.techniques CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.weakness_ordinality CASCADE;").executeUpdate();
            session.getTransaction().commit();

            // Closing session and session factory
            session.close();
            sf.close();
            // Putting CPE objects from CPE match feed file into database
            CPEobject.putIntoDatabase(); // file - https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip
            System.out.println("Actualization of CVE, CWE and CAPEC objects started");
            // Creating connection, session factory and session
            Configuration conn = new Configuration().configure().addAnnotatedClass(CVEobject.class).addAnnotatedClass(CPEobject.class)
                    .addAnnotatedClass(CVSS2object.class).addAnnotatedClass(CVSS3object.class).addAnnotatedClass(CPEnodeObject.class)
                    .addAnnotatedClass(ReferenceObject.class).addAnnotatedClass(CPEcomplexObj.class).addAnnotatedClass(CPEnodeToComplex.class)
                    .addAnnotatedClass(CAPECattStepObj.class).addAnnotatedClass(CAPECobject.class).addAnnotatedClass(CAPECrelationObj.class)
                    .addAnnotatedClass(CAPECskillObj.class).addAnnotatedClass(CWEalterTermObj.class).addAnnotatedClass(CWEapplPlatfObj.class)
                    .addAnnotatedClass(CWEconseqObj.class).addAnnotatedClass(CWEdemExObj.class).addAnnotatedClass(CWEdetMethObj.class)
                    .addAnnotatedClass(CWEexampCodeObj.class).addAnnotatedClass(CWEextRefRefObj.class).addAnnotatedClass(CWEintrModesObj.class)
                    .addAnnotatedClass(CWEnoteObj.class).addAnnotatedClass(CWEobject.class).addAnnotatedClass(CWEobsExObj.class)
                    .addAnnotatedClass(CWEpotMitObj.class).addAnnotatedClass(CWErelationObj.class).addAnnotatedClass(CWEtaxMapObj.class)
                    .addAnnotatedClass(CWEweakOrdObj.class);
            ServiceRegistry regg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build();
            SessionFactory sesf = conn.buildSessionFactory(regg);
            Session sessionc = sesf.openSession();
            // Going through each file given in input
            for (String fileName : fileNames) {
                // Taking objects returned by the CVEjsonToObjects() method
                List<CVEobject> cve_objs = CVEjsonToObjects(fileName, cwe_objs, cwes_to_remove);
                // Beginning transaction
                Transaction txv = sessionc.beginTransaction();
                // Putting CVE object and all the objects connected to CVE into database
                for (CVEobject obj : cve_objs) {
                    refresh++;
                    // Putting CVSS v2 object into database
                    if (!(obj.cvss_v2 == null)) sessionc.save(obj.cvss_v2);
                    // Putting CVSS v3 object into database
                    if (!(obj.cvss_v3 == null)) sessionc.save(obj.cvss_v3);
                    // Creating List for CWE removal from connections to prevent data redundance
                    List<CWEobject> cwe_to_remove = new ArrayList<>();
                    // Creating List for CWE connecting
                    List<CWEobject> cwes_to_add = new ArrayList<>();
                    // Putting related CWE and CAPEC objects into database
                    for (CWEobject cwe : obj.cwe) {
                        // If the CWE already exists in the database, only the connection between CWE and CVE will be made
                        if (sessionc.get(CWEobject.class, cwe.getCode_id()) != null) {
                            CWEobject cwe_to_add = (CWEobject) sessionc.get(CWEobject.class, cwe.getCode_id());
                            cwe_to_remove.add(cwe);
                            cwes_to_add.add(cwe_to_add);
                        } else {
                            // Creating List for CAPEC removal from connections to prevent data redundance
                            List<CAPECobject> capec_to_remove = new ArrayList<>();
                            // Creating List for CAPEC connecting
                            List<CAPECobject> capecs_to_add = new ArrayList<>();
                            // Putting related CAPEC objects into database
                            for (CAPECobject capec : cwe.getCapec()) {
                                // If the CAPEC already exists in the database, only the connection between CAPEC and CWE will be made
                                if (sessionc.get(CAPECobject.class, capec.getCapec_id()) != null) {
                                    CAPECobject capec_to_add = (CAPECobject) sessionc.get(CAPECobject.class, capec.getCapec_id());
                                    capec_to_remove.add(capec);
                                    capecs_to_add.add(capec_to_add);
                                } else {
                                    // Putting related CAPEC object into database
                                    sessionc.save(capec);
                                    // Putting CAPEC note objects into database
                                    for (CWEnoteObj note: capec.getNotes()) {
                                        note.setCapec(capec);
                                        sessionc.save(note);
                                    }
                                    // Putting CAPEC taxonomy mapping objects into database
                                    for (CWEtaxMapObj tax: capec.getTax_maps()) {
                                        tax.setCapec(capec);
                                        sessionc.save(tax);
                                    }
                                    // Putting CAPEC alternate term objects into database
                                    for (CWEalterTermObj alter: capec.getAlter_terms()) {
                                        alter.setCapec(capec);
                                        sessionc.save(alter);
                                    }
                                    // Putting external reference reference objects into database
                                    for (CWEextRefRefObj ext_ref_ref: capec.getExt_ref_refs()) {
                                        ext_ref_ref.setCapec(capec);
                                        sessionc.save(ext_ref_ref);
                                    }
                                    // Putting CAPEC consequence objects into database
                                    for (CWEconseqObj conseq: capec.getConsequences()) {
                                        conseq.setCapec(capec);
                                        sessionc.save(conseq);
                                    }
                                    // Putting CAPEC relation objects into database
                                    for (CAPECrelationObj relation: capec.getRelated_patterns()) {
                                        relation.setCapec(capec);
                                        sessionc.save(relation);
                                    }
                                    // Putting CAPEC attack step objects into database
                                    for (CAPECattStepObj att_step: capec.getAttack_steps()) {
                                        att_step.setCapec(capec);
                                        sessionc.save(att_step);
                                    }
                                    // Putting CAPEC skills required objects into database
                                    for (CAPECskillObj skill: capec.getSkills_required()) {
                                        skill.setCapec(capec);
                                        sessionc.save(skill);
                                    }
                                }
                            }
                            // CAPEC removal from connections to prevent data redundance
                            cwe.getCapec().removeAll(capec_to_remove);
                            // CAPEC connecting
                            cwe.getCapec().addAll(capecs_to_add);
                            // Putting CWE object into database
                            sessionc.save(cwe);
                            // Putting CWE relation objects into database
                            for (CWErelationObj rel: cwe.getRelations()) {
                                rel.setCwe(cwe);
                                sessionc.save(rel);
                            }
                            // Putting CWE applicable platform objects into database
                            for (CWEapplPlatfObj appl: cwe.getAppl_platform_objs()) {
                                appl.setCwe(cwe);
                                sessionc.save(appl);
                            }
                            // Putting CWE note objects into database
                            for (CWEnoteObj note: cwe.getNotes()) {
                                note.setCwe(cwe);
                                sessionc.save(note);
                            }
                            // Putting CWE introduction mode objects into database
                            for (CWEintrModesObj intr: cwe.getIntr_modes()) {
                                intr.setCwe(cwe);
                                sessionc.save(intr);
                            }
                            // Putting CWE consequence objects into database
                            for (CWEconseqObj conseq: cwe.getConsequences()) {
                                conseq.setCwe(cwe);
                                sessionc.save(conseq);
                            }
                            // Putting CWE alternate terms objects into database
                            for (CWEalterTermObj alter: cwe.getAlter_terms()) {
                                alter.setCwe(cwe);
                                sessionc.save(alter);
                            }
                            // Putting external reference reference objects into database
                            for (CWEextRefRefObj ext_ref_ref: cwe.getExt_ref_refs()) {
                                ext_ref_ref.setCwe(cwe);
                                sessionc.save(ext_ref_ref);
                            }
                            // Putting CWE taxonomy mapping objects into database
                            for (CWEtaxMapObj tax: cwe.getTax_maps()) {
                                tax.setCwe(cwe);
                                sessionc.save(tax);
                            }
                            // Putting CWE potential mitigation objects into database
                            for (CWEpotMitObj pot: cwe.getPot_mits()) {
                                pot.setCwe(cwe);
                                sessionc.save(pot);
                            }
                            // Putting CWE weakness ordinality objects into database
                            for (CWEweakOrdObj ord: cwe.getWeak_ords()) {
                                ord.setCwe(cwe);
                                sessionc.save(ord);
                            }
                            // Putting CWE demonstrative example objects into database
                            for (CWEdemExObj dem_ex: cwe.getDem_examples()) {
                                dem_ex.setCwe(cwe);
                                sessionc.save(dem_ex);
                                // Putting CWE CWE demonstrative example - example code objects into database
                                for (CWEexampCodeObj examp_code : dem_ex.getDem_ex_ex_codes()) {
                                    examp_code.setDem_ex(dem_ex);
                                    sessionc.save(examp_code);
                                }
                                // Putting CWE CWE demonstrative example - external reference reference objects into database
                                for (CWEextRefRefObj ext_ref_ref : dem_ex.getDem_ex_ext_ref_refs()) {
                                    ext_ref_ref.setDem_ex(dem_ex);
                                    sessionc.save(ext_ref_ref);
                                }
                            }
                            // Putting CWE observed example objects into database
                            for (CWEobsExObj obs_ex: cwe.getObs_examples()) {
                                obs_ex.setCwe(cwe);
                                sessionc.save(obs_ex);
                            }
                            // Putting CWE detection method objects into database
                            for (CWEdetMethObj det_met: cwe.getDet_meths()) {
                                det_met.setCwe(cwe);
                                sessionc.save(det_met);
                            }
                        }
                    }
                    // CWE removal from connections to prevent data redundance
                    obj.cwe.removeAll(cwe_to_remove);
                    // CWE connecting
                    obj.cwe.addAll(cwes_to_add);
                    // Putting CVE object into database
                    sessionc.save(obj);
                    // Putting CPE node objects into database
                    for (CPEnodeObject node_obj : obj.cpe_nodes) {
                        if (node_obj != null && node_obj.getComplex_cpe_objs() != null) {
                            for (CPEcomplexObj complex_cpe_obj : node_obj.getComplex_cpe_objs()) {
                                if (!(complex_cpe_obj == null)) {
                                    complex_cpe_obj.setCpe_objs(new ArrayList<>());
                                    Serializable cpe_spec_id = complex_cpe_obj.getCpe_id();
                                    CPEobject cpe_to_add = (CPEobject) sessionc.get(CPEobject.class, cpe_spec_id);
                                    // Connecting the right specific CPE object to the specific complex CPE object
                                    complex_cpe_obj.getCpe_objs().add(cpe_to_add);
                                    UUID uuid = UUID.randomUUID();
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "*" + uuid.toString()); // creating unique ID
                                    // Creating the relation between CVE, complex CPE and node object, adding also vulnerable attribute to it
                                    CPEnodeToComplex node_to_compl_cpe = new CPEnodeToComplex((obj.meta_data_id+"*"+complex_cpe_obj.getCpe_id()), complex_cpe_obj, node_obj, obj.meta_data_id, complex_cpe_obj.getVulnerable());
                                    // Putting CPE note to complex CPE object into database
                                    sessionc.save(node_to_compl_cpe);
                                    // Putting complex CPE object into database
                                    sessionc.save(complex_cpe_obj);
                                }
                            }
                            // Putting CPE node object into database
                            node_obj.setCve_obj(obj);
                            sessionc.save(node_obj);
                        } else if (node_obj != null) {
                            // Putting CPE node object into database
                            node_obj.setCve_obj(obj);
                            sessionc.save(node_obj);
                        }
                    }
                    for (ReferenceObject ref_obj : obj.references) {
                        // Putting CVE reference object into database
                        ref_obj.setCve_obj(obj);
                        sessionc.save(ref_obj);
                    }
                    // Ensuring optimalization
                    if (refresh % 250 == 0) {
                        txv.commit();
                        sessionc.close();
                        sessionc = sesf.openSession();
                        txv = sessionc.beginTransaction();
                    }
                }
                // Ending transaction
                if (txv.isActive()) txv.commit();
            }
            // Ending session
            if (sessionc.isOpen()) sessionc.close();

            // Removing connected CWE objects from original list for no data redundance in the database
            cwe_objs.removeAll(cwes_to_remove);

            // Opening session, beginning transaction
            sessionc = sesf.openSession();
            Transaction txv = sessionc.beginTransaction();

            // Putting the rest of CWE and CAPEC objects related to them into database
            for (CWEobject cwe : cwe_objs) {
                if (sessionc.get(CWEobject.class, cwe.getCode_id()) == null) {
                    // Creating List for CAPEC removal from connections to prevent data redundance
                    List<CAPECobject> capec_to_remove = new ArrayList<>();
                    // Creating List for CAPEC connecting
                    List<CAPECobject> capecs_to_add = new ArrayList<>();
                    // Putting related CAPEC objects into database
                    for (CAPECobject capec : cwe.getCapec()) {
                        // If the CAPEC already exists in the database, only the connection between CAPEC and CWE will be made
                        if (sessionc.get(CAPECobject.class, capec.getCapec_id()) != null) {
                            CAPECobject capec_to_add = (CAPECobject) sessionc.get(CAPECobject.class, capec.getCapec_id());
                            capec_to_remove.add(capec);
                            capecs_to_add.add(capec_to_add);
                        } else {
                            // Putting related CAPEC object into database
                            sessionc.save(capec);
                            // Putting CAPEC note objects into database
                            for (CWEnoteObj note: capec.getNotes()) {
                                note.setCapec(capec);
                                sessionc.save(note);
                            }
                            // Putting CAPEC taxonomy mapping objects into database
                            for (CWEtaxMapObj tax: capec.getTax_maps()) {
                                tax.setCapec(capec);
                                sessionc.save(tax);
                            }
                            // Putting CAPEC alternate term objects into database
                            for (CWEalterTermObj alter: capec.getAlter_terms()) {
                                alter.setCapec(capec);
                                sessionc.save(alter);
                            }
                            // Putting external reference reference objects into database
                            for (CWEextRefRefObj ext_ref_ref: capec.getExt_ref_refs()) {
                                ext_ref_ref.setCapec(capec);
                                sessionc.save(ext_ref_ref);
                            }
                            // Putting CAPEC consequence objects into database
                            for (CWEconseqObj conseq: capec.getConsequences()) {
                                conseq.setCapec(capec);
                                sessionc.save(conseq);
                            }
                            // Putting CAPEC relation objects into database
                            for (CAPECrelationObj relation: capec.getRelated_patterns()) {
                                relation.setCapec(capec);
                                sessionc.save(relation);
                            }
                            // Putting CAPEC attack step objects into database
                            for (CAPECattStepObj att_step: capec.getAttack_steps()) {
                                att_step.setCapec(capec);
                                sessionc.save(att_step);
                            }
                            // Putting CAPEC skills required objects into database
                            for (CAPECskillObj skill: capec.getSkills_required()) {
                                skill.setCapec(capec);
                                sessionc.save(skill);
                            }
                        }
                    }
                    // CAPEC removal from connections to prevent data redundance
                    cwe.getCapec().removeAll(capec_to_remove);
                    // CAPEC connecting
                    cwe.getCapec().addAll(capecs_to_add);
                    // Putting CWE object into database
                    sessionc.save(cwe);
                    // Putting CWE relation objects into database
                    for (CWErelationObj rel: cwe.getRelations()) {
                        rel.setCwe(cwe);
                        sessionc.save(rel);
                    }
                    // Putting CWE applicable platform objects into database
                    for (CWEapplPlatfObj appl: cwe.getAppl_platform_objs()) {
                        appl.setCwe(cwe);
                        sessionc.save(appl);
                    }
                    // Putting CWE note objects into database
                    for (CWEnoteObj note: cwe.getNotes()) {
                        note.setCwe(cwe);
                        sessionc.save(note);
                    }
                    // Putting CWE introduction mode objects into database
                    for (CWEintrModesObj intr: cwe.getIntr_modes()) {
                        intr.setCwe(cwe);
                        sessionc.save(intr);
                    }
                    // Putting CWE consequence objects into database
                    for (CWEconseqObj conseq: cwe.getConsequences()) {
                        conseq.setCwe(cwe);
                        sessionc.save(conseq);
                    }
                    // Putting CWE alternate terms objects into database
                    for (CWEalterTermObj alter: cwe.getAlter_terms()) {
                        alter.setCwe(cwe);
                        sessionc.save(alter);
                    }
                    // Putting external reference reference objects into database
                    for (CWEextRefRefObj ext_ref_ref: cwe.getExt_ref_refs()) {
                        ext_ref_ref.setCwe(cwe);
                        sessionc.save(ext_ref_ref);
                    }
                    // Putting CWE taxonomy mapping objects into database
                    for (CWEtaxMapObj tax: cwe.getTax_maps()) {
                        tax.setCwe(cwe);
                        sessionc.save(tax);
                    }
                    // Putting CWE potential mitigation objects into database
                    for (CWEpotMitObj pot: cwe.getPot_mits()) {
                        pot.setCwe(cwe);
                        sessionc.save(pot);
                    }
                    // Putting CWE weakness ordinality objects into database
                    for (CWEweakOrdObj ord: cwe.getWeak_ords()) {
                        ord.setCwe(cwe);
                        sessionc.save(ord);
                    }
                    // Putting CWE demonstrative example objects into database
                    for (CWEdemExObj dem_ex: cwe.getDem_examples()) {
                        dem_ex.setCwe(cwe);
                        sessionc.save(dem_ex);
                        // Putting CWE CWE demonstrative example - example code objects into database
                        for (CWEexampCodeObj examp_code : dem_ex.getDem_ex_ex_codes()) {
                            examp_code.setDem_ex(dem_ex);
                            sessionc.save(examp_code);
                        }
                        // Putting CWE CWE demonstrative example - external reference reference objects into database
                        for (CWEextRefRefObj ext_ref_ref : dem_ex.getDem_ex_ext_ref_refs()) {
                            ext_ref_ref.setDem_ex(dem_ex);
                            sessionc.save(ext_ref_ref);
                        }
                    }
                    // Putting CWE observed example objects into database
                    for (CWEobsExObj obs_ex: cwe.getObs_examples()) {
                        obs_ex.setCwe(cwe);
                        sessionc.save(obs_ex);
                    }
                    // Putting CWE detection method objects into database
                    for (CWEdetMethObj det_met: cwe.getDet_meths()) {
                        det_met.setCwe(cwe);
                        sessionc.save(det_met);
                    }
                }
            }

            // Committing transaction
            txv.commit();
            // Beginning transaction
            txv = sessionc.beginTransaction();

            // Putting the rest of CAPEC objects into database
            for (CAPECobject capec : capec_objs) {
                if (sessionc.get(CAPECobject.class, capec.getCapec_id()) == null) {
                    // Putting related CAPEC object into database
                    sessionc.save(capec);
                    // Putting CAPEC note objects into database
                    for (CWEnoteObj note: capec.getNotes()) {
                        note.setCapec(capec);
                        sessionc.save(note);
                    }
                    // Putting CAPEC taxonomy mapping objects into database
                    for (CWEtaxMapObj tax: capec.getTax_maps()) {
                        tax.setCapec(capec);
                        sessionc.save(tax);
                    }
                    // Putting CAPEC alternate term objects into database
                    for (CWEalterTermObj alter: capec.getAlter_terms()) {
                        alter.setCapec(capec);
                        sessionc.save(alter);
                    }
                    // Putting external reference reference objects into database
                    for (CWEextRefRefObj ext_ref_ref: capec.getExt_ref_refs()) {
                        ext_ref_ref.setCapec(capec);
                        sessionc.save(ext_ref_ref);
                    }
                    // Putting CAPEC consequence objects into database
                    for (CWEconseqObj conseq: capec.getConsequences()) {
                        conseq.setCapec(capec);
                        sessionc.save(conseq);
                    }
                    // Putting CAPEC relation objects into database
                    for (CAPECrelationObj relation: capec.getRelated_patterns()) {
                        relation.setCapec(capec);
                        sessionc.save(relation);
                    }
                    // Putting CAPEC attack step objects into database
                    for (CAPECattStepObj att_step: capec.getAttack_steps()) {
                        att_step.setCapec(capec);
                        sessionc.save(att_step);
                    }
                    // Putting CAPEC skills required objects into database
                    for (CAPECskillObj skill: capec.getSkills_required()) {
                        skill.setCapec(capec);
                        sessionc.save(skill);
                    }
                }
            }

            // Committing transaction
            txv.commit();
            // Ending session
            if (sessionc.isOpen()) sessionc.close();
            System.out.println("Actualization of CVE, CWE and CAPEC objects done");
        }

        // If the session is opened at the end, it will be closed
        if (session.isOpen()) session.close();
        // Closing session factory if its opened at the end
        if (sf.isOpen()) sf.close();
        if ((System.currentTimeMillis() - start_time) > 60000) System.out.println("Actualization of objects in database done, time elapsed: " + ((System.currentTimeMillis() - start_time) / 60000) + " minutes, files: " + Arrays.toString(fileNames));
        else System.out.println("Actualization of objects in database done, time elapsed: " + ((System.currentTimeMillis() - start_time) / 1000) + " seconds, files: " + Arrays.toString(fileNames));
    }

    ///**
    // * This method's purpose is to create CVE object from given parameters and return it
    // *
    // * @return CVE object
    // */
    //public static CVEobject getInstance(String data_type, String data_format, String data_version, String meta_data_id, String meta_data_assigner,
    //                                    List<CWEobject> cwe, List<ReferenceObject> references, List<String> descriptions,
    //                                    String cve_data_version, List<CPEnodeObject> cpe_nodes, CVSS2object cvss_v2, CVSS3object cvss_v3,
    //                                    double cvss_v2_base_score, double cvss_v3_base_score, Date published_date, Date last_modified_date) {

    //    return new CVEobject(data_type, data_format, data_version, meta_data_id, meta_data_assigner, cwe, references,
    //            descriptions, cve_data_version, cpe_nodes, cvss_v2, cvss_v3, cvss_v2_base_score, cvss_v3_base_score, published_date, last_modified_date);
    //}

    @Override
    public String toString() {
        return "CVEobject{" +
                "data_type='" + data_type + '\'' +
                ", data_format='" + data_format + '\'' +
                ", data_version='" + data_version + '\'' +
                ", meta_data_id='" + meta_data_id + '\'' +
                ", meta_data_assigner='" + meta_data_assigner + '\'' +
                ", related_cwe_objects=" + cwe +
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CVEobject)) return false;
        CVEobject cvEobject = (CVEobject) o;
        return Double.compare(cvEobject.cvss_v2_base_score, cvss_v2_base_score) == 0 && Double.compare(cvEobject.cvss_v3_base_score, cvss_v3_base_score) == 0 && Objects.equals(meta_data_id, cvEobject.meta_data_id) && Objects.equals(data_type, cvEobject.data_type) && Objects.equals(data_format, cvEobject.data_format) && Objects.equals(data_version, cvEobject.data_version) && Objects.equals(meta_data_assigner, cvEobject.meta_data_assigner) && Objects.equals(cwe, cvEobject.cwe) && Objects.equals(references, cvEobject.references) && Objects.equals(descriptions, cvEobject.descriptions) && Objects.equals(cve_data_version, cvEobject.cve_data_version) && Objects.equals(cpe_nodes, cvEobject.cpe_nodes) && Objects.equals(cvss_v2, cvEobject.cvss_v2) && Objects.equals(cvss_v3, cvEobject.cvss_v3) && Objects.equals(published_date, cvEobject.published_date) && Objects.equals(last_modified_date, cvEobject.last_modified_date);
    }

    @Override
    public int hashCode() {
        return Objects.hash(meta_data_id, data_type, data_format, data_version, meta_data_assigner, cwe, references, descriptions, cve_data_version, cpe_nodes, cvss_v2, cvss_v3, cvss_v2_base_score, cvss_v3_base_score, published_date, last_modified_date);
    }
}
