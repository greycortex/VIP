package basic_mitre.cve;

import basic_mitre.cpe.CPEcomplexObj;
import basic_mitre.cpe.CPEnodeObject;
import basic_mitre.cpe.CPEnodeToCPE;
import basic_mitre.cpe.CPEobject;
import basic_mitre.cvss.CVSS2object;
import basic_mitre.cvss.CVSS3object;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.persistence.*;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.Serializable;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * This class represents a CVE object (CPE matches (CPE objects), CVSS V2 (base metric v2) attributes, CVSS V3 (base metric v2) attributes, ...)
 * <p>
 * It can create and return all CVE objects from JSON file (input)
 * It can also put CVE objects and objects related to them into database
 * <p>
 * It also can create CVE object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity
@Table(name="cve", schema = "mitre")
public class CVEobject implements Serializable {

    public CVEobject() { } // default constructor

    @Id
    @Column(unique = true, name = "id")
    protected String meta_data_id;
    protected String data_type;
    protected String data_format;
    protected String data_version;
    protected String meta_data_assigner;
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
    protected Double cvss_v2_base_score;
    protected Double cvss_v3_base_score;
    protected Date published_date;
    protected Date last_modified_date;

    /**
     * Copies constructor
     *
     * @param data_type          data type parameter
     * @param data_format        data format parameter
     * @param data_version       data version parameter
     * @param meta_data_id       CVE meta data - ID parameter
     * @param meta_data_assigner CVE meta data - ASSIGNER parameter
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
                     List<ReferenceObject> references, List<String> descriptions, String cve_data_version, List<CPEnodeObject> cpe_nodes,
                     CVSS2object cvss_v2, CVSS3object cvss_v3, Double cvss_v2_base_score, Double cvss_v3_base_score, Date published_date,
                     Date last_modified_date) {

        this.data_type = data_type;
        this.data_format = data_format;
        this.data_version = data_version;
        this.meta_data_id = meta_data_id;
        this.meta_data_assigner = meta_data_assigner;
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

    public String getMeta_data_id() {
        return meta_data_id;
    }

    public String getData_type() {
        return data_type;
    }

    public void setData_type(String data_type) {
        this.data_type = data_type;
    }

    public List<ReferenceObject> getReferences() {
        return references;
    }

    public void setReferences(List<ReferenceObject> references) {
        this.references = references;
    }

    public List<String> getDescriptions() {
        return descriptions;
    }

    public void setDescriptions(List<String> descriptions) {
        this.descriptions = descriptions;
    }

    public Date getLast_modified_date() {
        return last_modified_date;
    }

    public void setLast_modified_date(Date last_modified_date) {
        this.last_modified_date = last_modified_date;
    }

    /**
     * This method's purpose is to create and return all CVE objects from JSON file (input)
     *
     * @param fileName path to the .json file with CVE objects
     * @return all created CVE objects
     */
    public static List<CVEobject> CVEjsonToObjects(String fileName) { // https://nvd.nist.gov/vuln/data-feeds - fileName

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

                    if (node.get("negate") != null) first_op = "N" + first_op;

                    JSONArray children = (JSONArray) node.get("children");
                    if (children != null && !children.isEmpty()) { // More complex structure
                        CPEnodeObject parent_node_obj = new CPEnodeObject(null, first_op, null);
                        cpe_nodes_final.add(parent_node_obj); // new parent CPE node object added

                        Iterator<JSONObject> children_iterator = children.iterator();

                        while (children_iterator.hasNext()) {
                            List<CPEcomplexObj> cpe_complex_objs = new ArrayList<>(); // complex CPE objects - CPE node object

                            JSONObject child = children_iterator.next();

                            String child_oper = (String) child.get("operator");
                            if (child.get("negate") != null) child_oper = "N" + child_oper;

                            JSONArray cpe_match = (JSONArray) child.get("cpe_match");
                            Iterator<JSONObject> cpe_iterator = cpe_match.iterator();
                            while (cpe_iterator.hasNext()) {
                                JSONObject cpe_match_specific = cpe_iterator.next();
                                String cpe23uri = (String) cpe_match_specific.get("cpe23Uri");
                                // Replacing problematic backslashes
                                cpe23uri = cpe23uri.replace("\\\\", "\\");
                                boolean vulnerable = (boolean) cpe_match_specific.get("vulnerable");
                                String version_start_excluding = (String) cpe_match_specific.get("versionStartExcluding");
                                if (version_start_excluding != null) {
                                    // Replacing problematic backslashes
                                    version_start_excluding = version_start_excluding.replace("\\\\", "\\");
                                }
                                String version_end_excluding = (String) cpe_match_specific.get("versionEndExcluding");
                                if (version_end_excluding != null) {
                                    // Replacing problematic backslashes
                                    version_end_excluding = version_end_excluding.replace("\\\\", "\\");
                                }
                                String version_start_including = (String) cpe_match_specific.get("versionStartIncluding");
                                if (version_start_including != null) {
                                    // Replacing problematic backslashes
                                    version_start_including = version_start_including.replace("\\\\", "\\");
                                }
                                String version_end_including = (String) cpe_match_specific.get("versionEndIncluding");
                                if (version_end_including != null) {
                                    // Replacing problematic backslashes
                                    version_end_including = version_end_including.replace("\\\\", "\\");
                                }
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

                        if (!cpe_match.isEmpty()) {
                            Iterator<JSONObject> cpe_iterator = cpe_match.iterator();
                            while (cpe_iterator.hasNext()) {
                                JSONObject cpe_match_specific = cpe_iterator.next();
                                String cpe23uri = (String) cpe_match_specific.get("cpe23Uri");
                                // Replacing problematic backslashes
                                cpe23uri = cpe23uri.replace("\\\\", "\\");
                                boolean vulnerable = (boolean) cpe_match_specific.get("vulnerable");
                                String version_start_excluding = (String) cpe_match_specific.get("versionStartExcluding");
                                if (version_start_excluding != null) {
                                    // Replacing problematic backslashes
                                    version_start_excluding = version_start_excluding.replace("\\\\", "\\");
                                }
                                String version_end_excluding = (String) cpe_match_specific.get("versionEndExcluding");
                                if (version_end_excluding != null) {
                                    // Replacing problematic backslashes
                                    version_end_excluding = version_end_excluding.replace("\\\\", "\\");
                                }
                                String version_start_including = (String) cpe_match_specific.get("versionStartIncluding");
                                if (version_start_including != null) {
                                    // Replacing problematic backslashes
                                    version_start_including = version_start_including.replace("\\\\", "\\");
                                }
                                String version_end_including = (String) cpe_match_specific.get("versionEndIncluding");
                                if (version_end_including != null) {
                                    // Replacing problematic backslashes
                                    version_end_including = version_end_including.replace("\\\\", "\\");
                                }
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
                Double base_score_v3_final = null;  // base_score_v3
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
                Double base_score_v2_final = null;  // base_score_v3
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
                        meta_data_assigner_final, references_final, descriptions_final, cve_data_version_final, cpe_nodes_final,
                        cvss_v2_final, cvss_v3_final, base_score_v2_final, base_score_v3_final, published_date_final,
                        last_modified_date_final));
            }
        } catch (IOException | ParseException | java.text.ParseException ex) {
            ex.printStackTrace();
        }

        // Returning all created CVE objects
        return cve_objs;
    }

    /**
     * This method's purpose is to put all given CVE objects and related objects into database
     *
     * @param cve_files paths to .json files with CVE objects
     * @param sf        object needed to get hibernate Session Factory and to work with database
     */
    public static void putIntoDatabase (String[] cve_files, SessionFactory sf) {
        // Creating Session, beginning transaction
        Session sessionc = sf.openSession();
        Transaction txv = sessionc.beginTransaction();

        // Counting to ensure optimalization later on
        int refresh = 0;

        // Going through each file given in input
        for (String fileName : cve_files) {
            // Taking objects returned by the CVEjsonToObjects() method
            List<CVEobject> cve_objs = CVEjsonToObjects(fileName);
            // Putting CVE object and all the objects connected to CVE into database
            for (CVEobject obj : cve_objs) {
                refresh++;
                // Putting CVSS v2 object into database
                if (obj.cvss_v2 != null) sessionc.save(obj.cvss_v2);
                // Putting CVSS v3 object into database
                if (obj.cvss_v3 != null) sessionc.save(obj.cvss_v3);
                // Putting CVE object into database
                sessionc.save(obj);
                // Putting CPE node objects into database
                for (CPEnodeObject node_obj : obj.cpe_nodes) {
                    if (node_obj != null && node_obj.getComplex_cpe_objs() != null) {
                        // Putting CPE node object into database
                        node_obj.setCve_obj(obj);
                        sessionc.save(node_obj);
                        for (CPEcomplexObj complex_cpe_obj : node_obj.getComplex_cpe_objs()) {
                            if (complex_cpe_obj != null) {
                                // Making basic CPE id for creating or getting CPE object later on
                                String basic_cpe_id = complex_cpe_obj.getCpe_id();
                                // ensuring unique ID of complex CPE object
                                if (complex_cpe_obj.getVersion_start_including() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#star_in_" + complex_cpe_obj.getVersion_start_including());
                                }
                                if (complex_cpe_obj.getVersion_start_excluding() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#star_ex_" + complex_cpe_obj.getVersion_start_excluding());
                                }
                                if (complex_cpe_obj.getVersion_end_including() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#end_in_" + complex_cpe_obj.getVersion_end_including());
                                }
                                if (complex_cpe_obj.getVersion_end_excluding() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#end_ex_" + complex_cpe_obj.getVersion_end_excluding());
                                }

                                CPEcomplexObj compl_cpe_db = null;
                                CPEobject cpe_db = null;
                                // Figuring out if it will be complex or basic CPE object - following is the complex CPE case
                                if (complex_cpe_obj.getVersion_end_excluding() != null || complex_cpe_obj.getVersion_start_excluding() != null ||
                                complex_cpe_obj.getVersion_end_including() != null || complex_cpe_obj.getVersion_start_including() != null) {
                                    compl_cpe_db = (CPEcomplexObj) sessionc.get(CPEcomplexObj.class, complex_cpe_obj.getCpe_id());
                                    // Making connection if the complex CPE object already exists
                                    if (compl_cpe_db != null) {
                                        if (sessionc.get(CPEnodeToCPE.class, (obj.meta_data_id + "#" + compl_cpe_db.getCpe_id() + "#" + node_obj.getId())) == null) {
                                            // Creating connection between CPE and CVE
                                            CPEnodeToCPE node_to_cpe = new CPEnodeToCPE((obj.meta_data_id + "#" + compl_cpe_db.getCpe_id() + "#" + node_obj.getId()), compl_cpe_db, node_obj, obj.meta_data_id, complex_cpe_obj.getVulnerable(), null);
                                            // Putting CPE node to CPE object into database
                                            sessionc.save(node_to_cpe);
                                        }
                                    }
                                    // Creating new complex CPE object if it doesn't exist
                                    else {
                                        // Creating basic CPE object to connect with if it doesn't exist
                                        cpe_db = (CPEobject) sessionc.get(CPEobject.class, basic_cpe_id);
                                        if (cpe_db == null) {
                                            cpe_db = CPEobject.cpeUriToObject(basic_cpe_id);
                                            sessionc.save(cpe_db);
                                        }
                                        complex_cpe_obj.setCpe_objs(new ArrayList<>());
                                        // Making connection between complex CPE object and basic CPE object
                                        complex_cpe_obj.getCpe_objs().add(cpe_db);
                                        // Ensuring unique ID and putting complex CPE object into database
                                        complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id()+"#"+obj.meta_data_id);
                                        sessionc.save(complex_cpe_obj);
                                        // Making connection between complex CPE object and CVE object
                                        CPEnodeToCPE node_to_cpe = new CPEnodeToCPE((obj.meta_data_id+"#"+complex_cpe_obj.getCpe_id()+"#"+node_obj.getId()), complex_cpe_obj, node_obj, obj.meta_data_id, complex_cpe_obj.getVulnerable(), null);
                                        // Putting CPE node to CPE object into database
                                        sessionc.save(node_to_cpe);
                                    }
                                }
                                // Following is the basic CPE case
                                else {
                                    // If the basic CPE object does exist, just the connection will be made
                                    cpe_db = (CPEobject) sessionc.get(CPEobject.class, basic_cpe_id);
                                    if (cpe_db != null) {
                                        if (sessionc.get(CPEnodeToCPE.class, (obj.meta_data_id+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId())) == null) {
                                            // Creating connection between basic CPE object and CVE
                                            CPEnodeToCPE node_to_cpe = new CPEnodeToCPE((obj.meta_data_id+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId()), null, node_obj, obj.meta_data_id, complex_cpe_obj.getVulnerable(), cpe_db);
                                            // Putting CPE node to CPE object into database
                                            sessionc.save(node_to_cpe);
                                        }
                                    }
                                    // If the basic CPE object doesn't exist, it will be created and put into database
                                    else {
                                        cpe_db = CPEobject.cpeUriToObject(basic_cpe_id);
                                        sessionc.save(cpe_db);
                                        // Creating connection between basic CPE object and CVE
                                        CPEnodeToCPE node_to_cpe = new CPEnodeToCPE((obj.meta_data_id+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId()), null, node_obj, obj.meta_data_id, complex_cpe_obj.getVulnerable(), cpe_db);
                                        // Putting CPE node to CPE object into database
                                        sessionc.save(node_to_cpe);
                                    }
                                }
                            }
                        }
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
                    sessionc = sf.openSession();
                    txv = sessionc.beginTransaction();
                }
            }
            System.out.println("CVE data from file '" + fileName + "' were put into the database");
        }
        // Ending session and committing transaction
        if (txv.isActive()) txv.commit();
        if (sessionc.isOpen()) sessionc.close();
        System.out.println("CVE data were put into the database");
    }

    ///**
    // * This method's purpose is to create CVE object from given parameters and return it
    // *
    // * @return CVE object
    // */
    //public static CVEobject getInstance(String data_type, String data_format, String data_version, String meta_data_id,
    //                                    String meta_data_assigner, List<ReferenceObject> references, List<String> descriptions,
    //                                    String cve_data_version, List<CPEnodeObject> cpe_nodes, CVSS2object cvss_v2, CVSS3object cvss_v3,
    //                                    double cvss_v2_base_score, double cvss_v3_base_score, Date published_date, Date last_modified_date) {

    //    return new CVEobject(data_type, data_format, data_version, meta_data_id, meta_data_assigner, references,
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
        return Objects.equals(meta_data_id, cvEobject.meta_data_id) && Objects.equals(data_type, cvEobject.data_type) && Objects.equals(data_format, cvEobject.data_format) && Objects.equals(data_version, cvEobject.data_version) && Objects.equals(meta_data_assigner, cvEobject.meta_data_assigner) && Objects.equals(references, cvEobject.references) && Objects.equals(descriptions, cvEobject.descriptions) && Objects.equals(cve_data_version, cvEobject.cve_data_version) && Objects.equals(cpe_nodes, cvEobject.cpe_nodes) && Objects.equals(cvss_v2, cvEobject.cvss_v2) && Objects.equals(cvss_v3, cvEobject.cvss_v3) && Objects.equals(cvss_v2_base_score, cvEobject.cvss_v2_base_score) && Objects.equals(cvss_v3_base_score, cvEobject.cvss_v3_base_score) && Objects.equals(published_date, cvEobject.published_date) && Objects.equals(last_modified_date, cvEobject.last_modified_date);
    }

    @Override
    public int hashCode() {
        return Objects.hash(meta_data_id, data_type, data_format, data_version, meta_data_assigner, references, descriptions, cve_data_version, cpe_nodes, cvss_v2, cvss_v3, cvss_v2_base_score, cvss_v3_base_score, published_date, last_modified_date);
    }
}
