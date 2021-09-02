package extended_mitre.cve;

import extended_mitre.cpe.CPEnodeToCPE;
import extended_mitre.cvss.CVSS3object;
import extended_mitre.cvss.CVSS2object;
import extended_mitre.cpe.CPEcomplexObj;
import extended_mitre.cpe.CPEobject;
import extended_mitre.cpe.CPEnodeObject;
import extended_mitre.cwe.*;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
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
 * It can also put CVE objects and objects related to them into database
 * It can also perform a quick actualization of CVE and CPE data in the database
 * <p>
 * It also can create CVE object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "cve")
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
                     CVSS2object cvss_v2, CVSS3object cvss_v3, Double cvss_v2_base_score, Double cvss_v3_base_score, Date published_date,
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

    public String getMeta_data_id() {
        return meta_data_id;
    }

    public String getData_type() {
        return data_type;
    }

    public void setData_type(String data_type) {
        this.data_type = data_type;
    }

    public List<CWEobject> getCwe() {
        return cwe;
    }

    public void setCwe(List<CWEobject> cwe) {
        this.cwe = cwe;
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

    public String getData_format() {
        return data_format;
    }

    public void setData_format(String data_format) {
        this.data_format = data_format;
    }

    public String getData_version() {
        return data_version;
    }

    public void setData_version(String data_version) {
        this.data_version = data_version;
    }

    public String getMeta_data_assigner() {
        return meta_data_assigner;
    }

    public void setMeta_data_assigner(String meta_data_assigner) {
        this.meta_data_assigner = meta_data_assigner;
    }

    public String getCve_data_version() {
        return cve_data_version;
    }

    public void setCve_data_version(String cve_data_version) {
        this.cve_data_version = cve_data_version;
    }

    public List<CPEnodeObject> getCpe_nodes() {
        return cpe_nodes;
    }

    public CVSS2object getCvss_v2() {
        return cvss_v2;
    }

    public void setCvss_v2(CVSS2object cvss_v2) {
        this.cvss_v2 = cvss_v2;
    }

    public CVSS3object getCvss_v3() {
        return cvss_v3;
    }

    public void setCvss_v3(CVSS3object cvss_v3) {
        this.cvss_v3 = cvss_v3;
    }

    public Double getCvss_v2_base_score() {
        return cvss_v2_base_score;
    }

    public void setCvss_v2_base_score(Double cvss_v2_base_score) {
        this.cvss_v2_base_score = cvss_v2_base_score;
    }

    public Double getCvss_v3_base_score() {
        return cvss_v3_base_score;
    }

    public void setCvss_v3_base_score(Double cvss_v3_base_score) {
        this.cvss_v3_base_score = cvss_v3_base_score;
    }

    public Date getPublished_date() {
        return published_date;
    }

    public void setPublished_date(Date published_date) {
        this.published_date = published_date;
    }

    /**
     * This method's purpose is to create and return all CVE objects from JSON file (input)
     *
     * @param fileName path to the .json file with CVE objects
     * @param cwe_objects existing CWE objects for search of the relating ones
     * @return all created CVE objects
     */
    public static List<CVEobject> CVEjsonToObjects(String fileName, List<CWEobject> cwe_objects) { // https://nvd.nist.gov/vuln/data-feeds - fileName

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
                List<CWEobject> cwe_objs_final = new ArrayList<>(); // problem_type_data - CWE objects
                if (cwe_objects != null) {
                    JSONObject problemtype = (JSONObject) cve.get("problemtype");
                    JSONArray problemtype_data = (JSONArray) problemtype.get("problemtype_data");
                    Iterator<JSONObject> problem_iterator = problemtype_data.iterator();
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
                                }
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

                    if (node.get("negate") != null) first_op = "N" + first_op;

                    JSONArray children = (JSONArray) node.get("children");
                    if (children != null && !children.isEmpty()) { // More complex structure
                        CPEnodeObject parent_node_obj = new CPEnodeObject(null, first_op, null, null, null);
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
                                CPEobject cpe_normal_obj = CPEobject.cpeUriToObject(cpe23uri); // create method from CPEobject class used - normal CPE object
                                cpe_complex_objs.add(CPEcomplexObj.getInstanceFromCPE(cpe_normal_obj, vulnerable,
                                        version_start_excluding, version_end_excluding, version_start_including, version_end_including)); // CPEcompexObj class used - more complex CPE object

                            }
                            CPEnodeObject child_obj = new CPEnodeObject(cpe_complex_objs, child_oper, parent_node_obj, null, null); // creating child CPE node object (also creating relation with parent object)
                            // Adding child object to parent's child object List
                            if (parent_node_obj.getChildren() == null) {
                                List<CPEnodeObject> child_nodes_spec = new ArrayList<>();
                                child_nodes_spec.add(child_obj);
                                parent_node_obj.setChildren(child_nodes_spec);
                            }
                            else {
                                parent_node_obj.getChildren().add(child_obj);
                            }

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
                                CPEobject cpe_normal_obj = CPEobject.cpeUriToObject(cpe23uri); // create method from CPEobject class used - normal CPE object
                                cpe_complex_objs.add(CPEcomplexObj.getInstanceFromCPE(cpe_normal_obj, vulnerable,
                                        version_start_excluding, version_end_excluding, version_start_including, version_end_including)); // CPEcompexObj class used - more complex CPE object
                            }
                        }
                        cpe_nodes_final.add(new CPEnodeObject(cpe_complex_objs, first_op, null, null, null)); // CPE node object added
                    }
                }

                // Getting impact JSON object
                JSONObject impact = (JSONObject) cve_item.get("impact");

                // Getting CVSS v3 (base metric v3) object
                CVSS3object cvss_v3_final = null; // cvss_v3
                Double base_score_v3_final = null;  // base_score_v3
                if (impact.get("baseMetricV3") != null) {
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
                if (impact.get("baseMetricV2") != null) {
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
                    if (base_metric_v2.get("acInsufInfo") != null) {
                        boolean ac_insuf_info_v2_boolean = (boolean) base_metric_v2.get("acInsufInfo");

                        if (ac_insuf_info_v2_boolean) ac_insuf_info_v2 = "true";
                        else ac_insuf_info_v2 = "false";
                    }
                    if (base_metric_v2.get("obtainAllPrivilege") != null) {
                        boolean obtain_all_privilege_v2_boolean = (boolean) base_metric_v2.get("obtainAllPrivilege");

                        if (obtain_all_privilege_v2_boolean) obtain_all_privilege_v2 = "true";
                        else obtain_all_privilege_v2 = "false";
                    }
                    if (base_metric_v2.get("obtainUserPrivilege") != null) {
                        boolean obtain_user_privilege_v2_boolean = (boolean) base_metric_v2.get("obtainUserPrivilege");

                        if (obtain_user_privilege_v2_boolean) obtain_user_privilege_v2 = "true";
                        else obtain_user_privilege_v2 = "false";
                    }
                    if (base_metric_v2.get("obtainOtherPrivilege") != null) {
                        boolean obtain_other_privilege_v2_boolean = (boolean) base_metric_v2.get("obtainOtherPrivilege");

                        if (obtain_other_privilege_v2_boolean) obtain_other_privilege_v2 = "true";
                        else obtain_other_privilege_v2 = "false";
                    }
                    if (base_metric_v2.get("userInteractionRequired") != null) {
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
     * This method's purpose is to put all given CVE objects and related objects into database
     * It uses the putIntoDatabaseCore() method for this purpose
     *
     * @param cve_files paths to .json files with CVE objects
     * @param cwe_objs  parsed CWE objects needed for making relation between them and CVE objects
     * @param sf        object needed to get hibernate Session Factory and to work with database
     */
    public static void putIntoDatabase (String[] cve_files, List<CWEobject> cwe_objs, SessionFactory sf) {
        // Going through each file given in input
        for (String fileName : cve_files) {
            // Taking objects returned by the CVEjsonToObjects() method
            List<CVEobject> cve_objs = CVEjsonToObjects(fileName, cwe_objs);
            // Putting all given CVE objects into the database
            putIntoDatabaseCore(cve_objs, sf);
            System.out.println("CVE data from file '" + fileName + "' were put into the database");
        }
        System.out.println("CVE data were put into the database");
    }

    /**
     * This method's purpose is to put all given CVE objects and related objects into database
     *
     * @param cve_objs  List of CVE objects to put into the database
     * @param sf        object needed to get hibernate Session Factory and to work with database
     */
    public static void putIntoDatabaseCore(List<CVEobject> cve_objs, SessionFactory sf) {
        // Creating Session, beginning transaction
        Session sessionc = sf.openSession();
        Transaction txv = sessionc.beginTransaction();

        // Counting to ensure optimalization later on
        int refresh = 0;

        // Putting CVE object and all the objects connected to CVE into database
        for (CVEobject obj : cve_objs) {
            refresh++;
            // Putting CVSS v2 object into database
            if (obj.cvss_v2 != null) sessionc.save(obj.cvss_v2);
            // Putting CVSS v3 object into database
            if (obj.cvss_v3 != null) sessionc.save(obj.cvss_v3);
            // Creating List for CWE connecting
            List<CWEobject> cwes_to_add = new ArrayList<>();
            // Making connections with related CWE objects
            for (CWEobject cwe : obj.cwe) {
                // Connection between CWE and CVE will be made
                CWEobject cwe_to_add = (CWEobject) sessionc.get(CWEobject.class, cwe.getCode_id());
                if (cwe_to_add != null) {
                    cwes_to_add.add(cwe_to_add);
                }
            }
            // CWE connecting
            obj.cwe = new ArrayList<>();
            obj.cwe.addAll(cwes_to_add);
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
                            CPEcomplexObj compl_cpe_db_com = null;
                            CPEobject cpe_db = null;
                            // Figuring out if it will be complex or basic CPE object - following is the complex CPE case
                            if (complex_cpe_obj.getVersion_end_excluding() != null || complex_cpe_obj.getVersion_start_excluding() != null ||
                                    complex_cpe_obj.getVersion_end_including() != null || complex_cpe_obj.getVersion_start_including() != null) {
                                compl_cpe_db = (CPEcomplexObj) sessionc.get(CPEcomplexObj.class, complex_cpe_obj.getCpe_id());
                                compl_cpe_db_com = (CPEcomplexObj) sessionc.get(CPEcomplexObj.class, complex_cpe_obj.getCpe_id()+"#"+obj.meta_data_id);
                                // Making connection if the complex CPE object already exists
                                if (compl_cpe_db != null) {
                                    if (sessionc.get(CPEnodeToCPE.class, (obj.meta_data_id + "#" + compl_cpe_db.getCpe_id() + "#" + node_obj.getId())) == null) {
                                        // Creating connection between CPE and CVE
                                        CPEnodeToCPE node_to_cpe = new CPEnodeToCPE((obj.meta_data_id + "#" + compl_cpe_db.getCpe_id() + "#" + node_obj.getId()), compl_cpe_db, node_obj, obj.meta_data_id, complex_cpe_obj.getVulnerable(), null);
                                        // Putting CPE node to CPE object into database
                                        sessionc.save(node_to_cpe);
                                    }
                                }
                                else if (compl_cpe_db_com != null) {
                                    if (sessionc.get(CPEnodeToCPE.class, (obj.meta_data_id + "#" + compl_cpe_db_com.getCpe_id() + "#" + node_obj.getId())) == null) {
                                        // Creating connection between CPE and CVE
                                        CPEnodeToCPE node_to_cpe = new CPEnodeToCPE((obj.meta_data_id + "#" + compl_cpe_db_com.getCpe_id() + "#" + node_obj.getId()), compl_cpe_db_com, node_obj, obj.meta_data_id, complex_cpe_obj.getVulnerable(), null);
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
        // Ending session and committing transaction
        if (txv.isActive()) txv.commit();
        if (sessionc.isOpen()) sessionc.close();
    }

    /**
     * This method's purpose is to quickly update CVE and CPE objects in the database
     *
     * @param session   Session object needed for working with the database
     * @param cve_db    CVE object from the database that will be actualized
     * @param cve_obj   CVE object from file that will used for actualization
     */
    public static void quickUpdateCore (Session session, CVEobject cve_db, CVEobject cve_obj) {

        // Controlling changes in CVSS v2 data
        // If there is a change in CVSS v2 data, the data in the database will be changed
        if (cve_db.getCvss_v2() != null && cve_obj.getCvss_v2() != null && !cve_db.getCvss_v2().equals(cve_obj.getCvss_v2())) {
            CVSS2object cvss2_db = cve_db.getCvss_v2();
            CVSS2object cvss2_new = cve_obj.getCvss_v2();
            session.evict(cvss2_db);
            if (!cvss2_db.getVersion().equals(cvss2_new.getVersion())) cvss2_db.setVersion(cvss2_new.getVersion());
            if (!cvss2_db.getVector_string().equals(cvss2_new.getVector_string())) cvss2_db.setVector_string(cvss2_new.getVector_string());
            if (!cvss2_db.getAccess_vector().equals(cvss2_new.getAccess_vector())) cvss2_db.setAccess_vector(cvss2_new.getAccess_vector());
            if (!cvss2_db.getAccess_complexity().equals(cvss2_new.getAccess_complexity())) cvss2_db.setAccess_complexity(cvss2_new.getAccess_complexity());
            if (!cvss2_db.getAuthentication().equals(cvss2_new.getAuthentication())) cvss2_db.setAuthentication(cvss2_new.getAuthentication());
            if (!cvss2_db.getConfidentiality_impact().equals(cvss2_new.getConfidentiality_impact())) cvss2_db.setConfidentiality_impact(cvss2_new.getConfidentiality_impact());
            if (!cvss2_db.getIntegrity_impact().equals(cvss2_new.getIntegrity_impact())) cvss2_db.setIntegrity_impact(cvss2_new.getIntegrity_impact());
            if (!cvss2_db.getAvailability_impact().equals(cvss2_new.getAvailability_impact())) cvss2_db.setAvailability_impact(cvss2_new.getAvailability_impact());
            if (cvss2_db.getBase_score_v2() != cvss2_new.getBase_score_v2()) cvss2_db.setBase_score_v2(cvss2_new.getBase_score_v2());
            if (!cvss2_db.getSeverity().equals(cvss2_new.getSeverity())) cvss2_db.setSeverity(cvss2_new.getSeverity());
            if (cvss2_db.getExploitability_score_v2() != cvss2_new.getExploitability_score_v2()) cvss2_db.setExploitability_score_v2(cvss2_new.getExploitability_score_v2());
            if (cvss2_db.getImpact_score_v2() != cvss2_new.getImpact_score_v2()) cvss2_db.setImpact_score_v2(cvss2_new.getImpact_score_v2());
            if (!cvss2_db.getAc_insuf_info().equals(cvss2_new.getAc_insuf_info())) cvss2_db.setAc_insuf_info(cvss2_new.getAc_insuf_info());
            if (!cvss2_db.getObtain_all_privilege().equals(cvss2_new.getObtain_all_privilege())) cvss2_db.setObtain_all_privilege(cvss2_new.getObtain_all_privilege());
            if (!cvss2_db.getObtain_user_privilege().equals(cvss2_new.getObtain_user_privilege())) cvss2_db.setObtain_user_privilege(cvss2_new.getObtain_user_privilege());
            if (!cvss2_db.getObtain_other_privilege().equals(cvss2_new.getObtain_other_privilege())) cvss2_db.setObtain_other_privilege(cvss2_new.getObtain_other_privilege());
            if (!cvss2_db.getUser_interaction_required().equals(cvss2_new.getUser_interaction_required())) cvss2_db.setUser_interaction_required(cvss2_new.getUser_interaction_required());
            session.merge(cvss2_db);
        }
        // If new object is detected, it will be associated and saved into the database
        else if (cve_db.getCvss_v2() == null && cve_obj.getCvss_v2() != null) {
            cve_db.setCvss_v2(cve_obj.getCvss_v2());
            session.save(cve_db.getCvss_v2());
        }
        // If deletion of object is detected, the old object will be deleted from the database
        else if (cve_db.getCvss_v2() != null && cve_obj.getCvss_v2() == null) {
            session.remove(cve_db.getCvss_v2());
        }

        // Controlling changes in CVSS v3 data
        // If there is a change in CVSS v3 data, the data in the database will be changed
        if (cve_db.getCvss_v3() != null && cve_obj.getCvss_v3() != null && !cve_db.getCvss_v3().equals(cve_obj.getCvss_v3())) {
            CVSS3object cvss3_db = cve_db.getCvss_v3();
            CVSS3object cvss3_new = cve_obj.getCvss_v3();
            session.evict(cvss3_db);
            if (!cvss3_db.getVersion().equals(cvss3_new.getVersion())) cvss3_db.setVersion(cvss3_new.getVersion());
            if (!cvss3_db.getVector_string().equals(cvss3_new.getVector_string())) cvss3_db.setVector_string(cvss3_new.getVector_string());
            if (!cvss3_db.getAttack_vector().equals(cvss3_new.getAttack_vector())) cvss3_db.setAttack_vector(cvss3_new.getAttack_vector());
            if (!cvss3_db.getAttack_complexity().equals(cvss3_new.getAttack_complexity())) cvss3_db.setAttack_complexity(cvss3_new.getAttack_complexity());
            if (!cvss3_db.getPrivileges_required().equals(cvss3_new.getPrivileges_required())) cvss3_db.setPrivileges_required(cvss3_new.getPrivileges_required());
            if (!cvss3_db.getUser_interaction().equals(cvss3_new.getUser_interaction())) cvss3_db.setUser_interaction(cvss3_new.getUser_interaction());
            if (!cvss3_db.getScope().equals(cvss3_new.getScope())) cvss3_db.setScope(cvss3_new.getScope());
            if (!cvss3_db.getConfidentiality_impact().equals(cvss3_new.getConfidentiality_impact())) cvss3_db.setConfidentiality_impact(cvss3_new.getConfidentiality_impact());
            if (!cvss3_db.getIntegrity_impact().equals(cvss3_new.getIntegrity_impact())) cvss3_db.setIntegrity_impact(cvss3_new.getIntegrity_impact());
            if (!cvss3_db.getAvailability_impact().equals(cvss3_new.getAvailability_impact())) cvss3_db.setAvailability_impact(cvss3_new.getAvailability_impact());
            if (cvss3_db.getBase_score_v3() != cvss3_new.getBase_score_v3()) cvss3_db.setBase_score_v3(cvss3_new.getBase_score_v3());
            if (!cvss3_db.getBase_severity_v3().equals(cvss3_new.getBase_severity_v3())) cvss3_db.setBase_severity_v3(cvss3_new.getBase_severity_v3());
            if (cvss3_db.getExploitability_score_v3() != cvss3_new.getExploitability_score_v3()) cvss3_db.setExploitability_score_v3(cvss3_new.getExploitability_score_v3());
            if (cvss3_db.getImpact_score_v3() != cvss3_new.getImpact_score_v3()) cvss3_db.setImpact_score_v3(cvss3_new.getImpact_score_v3());
            session.merge(cvss3_db);
        }
        // If new object is detected, it will be associated and saved into the database
        else if (cve_db.getCvss_v3() == null && cve_obj.getCvss_v3() != null) {
            cve_db.setCvss_v3(cve_obj.getCvss_v3());
            session.save(cve_db.getCvss_v3());
        }
        // If deletion of object is detected, the old object will be deleted from the database
        else if (cve_db.getCvss_v3() != null && cve_obj.getCvss_v3() == null) {
            session.remove(cve_db.getCvss_v3());
        }

        // Controlling changes in CVE core data
        // If there is a change in CVE core data, the data in the database will be changed
        if (!cve_db.equals(cve_obj)) {
            session.evict(cve_db);
            if (!cve_db.getData_type().equals(cve_obj.getData_type())) cve_db.setData_type(cve_obj.getData_type());
            if (!cve_db.getData_format().equals(cve_obj.getData_format())) cve_db.setData_format(cve_obj.getData_format());
            if (!cve_db.getData_version().equals(cve_obj.getData_version())) cve_db.setData_version(cve_obj.getData_version());
            if (!cve_db.getMeta_data_assigner().equals(cve_obj.getMeta_data_assigner())) cve_db.setMeta_data_assigner(cve_obj.getMeta_data_assigner());

            if (cve_db.getDescriptions() != null && cve_obj.getDescriptions() != null) {
                if (!cve_db.getDescriptions().equals(cve_obj.getDescriptions())) cve_db.setDescriptions(cve_obj.getDescriptions());
            }
            else if (cve_db.getDescriptions() == null && cve_obj.getDescriptions() != null) {
                cve_db.setDescriptions(cve_obj.getDescriptions());
            }
            else if (cve_db.getDescriptions() != null && cve_obj.getDescriptions() == null) {
                cve_db.setDescriptions(null);
            }

            if (cve_db.getCve_data_version() != null && cve_obj.getCve_data_version() != null) {
                if (!cve_db.getCve_data_version().equals(cve_obj.getCve_data_version())) cve_db.setCve_data_version(cve_obj.getCve_data_version());
            }
            else if (cve_db.getCve_data_version() == null && cve_obj.getCve_data_version() != null) {
                cve_db.setCve_data_version(cve_obj.getCve_data_version());
            }
            else if (cve_db.getCve_data_version() != null && cve_obj.getCve_data_version() == null) {
                cve_db.setCve_data_version(null);
            }

            if (cve_db.getCvss_v2_base_score() != null && cve_obj.getCvss_v2_base_score() != null) {
                if (!cve_db.getCvss_v2_base_score().equals(cve_obj.getCvss_v2_base_score())) cve_db.setCvss_v2_base_score(cve_obj.getCvss_v2_base_score());
            }
            else if (cve_db.getCvss_v2_base_score() == null && cve_obj.getCvss_v2_base_score() != null) {
                cve_db.setCvss_v2_base_score(cve_obj.getCvss_v2_base_score());
            }
            else if (cve_db.getCvss_v2_base_score() != null && cve_obj.getCvss_v2_base_score() == null) {
                cve_db.setCvss_v2_base_score(null);
            }

            if (cve_db.getCvss_v3_base_score() != null && cve_obj.getCvss_v3_base_score() != null) {
                if (!cve_db.getCvss_v3_base_score().equals(cve_obj.getCvss_v3_base_score())) cve_db.setCvss_v3_base_score(cve_obj.getCvss_v3_base_score());
            }
            else if (cve_db.getCvss_v3_base_score() == null && cve_obj.getCvss_v3_base_score() != null) {
                cve_db.setCvss_v3_base_score(cve_obj.getCvss_v3_base_score());
            }
            else if (cve_db.getCvss_v3_base_score() != null && cve_obj.getCvss_v3_base_score() == null) {
                cve_db.setCvss_v3_base_score(null);
            }

            if (!cve_db.getPublished_date().equals(cve_obj.getPublished_date())) cve_db.setPublished_date(cve_obj.getPublished_date());
            if (!cve_db.getLast_modified_date().equals(cve_obj.getLast_modified_date())) cve_db.setLast_modified_date(cve_obj.getLast_modified_date());
            session.merge(cve_db);
        }

        // Controlling changes in CVE Reference data
        // If there is a change in CVE Reference data, the data in the database will be changed
        if (cve_db.getReferences() != null && cve_obj.getReferences() != null && !cve_db.getReferences().equals(cve_obj.getReferences())) {
            List<ReferenceObject> refs_to_save = new ArrayList<>();
            List<Integer> dup_indexes_db = new ArrayList<>();
            // Searching for not changed objects
            for (int i = 0; i < cve_obj.getReferences().size(); i++) {
                boolean equals = false;
                for (int j = 0; j < cve_db.getReferences().size(); j++) {
                    if (cve_obj.getReferences().get(i).equals(cve_db.getReferences().get(j))) {
                        equals = true;
                        dup_indexes_db.add(j);
                        break;
                    }
                }
                // If there is a change, an update will be made later on
                if (!equals) {
                    refs_to_save.add(cve_obj.getReferences().get(i));
                }
            }
            List<ReferenceObject> db_refs_to_remove = new ArrayList<>();
            for (int i = 0; i < cve_db.getReferences().size(); i++) {
                if (!dup_indexes_db.contains(i)) {
                    // Merging old objects for change with up-to-date objects for change so we don't delete that much
                    if (!refs_to_save.isEmpty()) {
                        ReferenceObject ref_db = cve_db.getReferences().get(i);
                        ReferenceObject ref_new = refs_to_save.get(0);
                        session.evict(ref_db);

                        if (ref_db.getUrl() != null && ref_new.getUrl() != null) {
                            if (!ref_db.getUrl().equals(ref_new.getUrl())) ref_db.setUrl(ref_new.getUrl());
                        }
                        else if (ref_db.getUrl() == null && ref_new.getUrl() != null) {
                            ref_db.setUrl(ref_new.getUrl());
                        }
                        else if (ref_db.getUrl() != null && ref_new.getUrl() == null) {
                            ref_db.setUrl(null);
                        }

                        if (ref_db.getName() != null && ref_new.getName() != null) {
                            if (!ref_db.getName().equals(ref_new.getName())) ref_db.setName(ref_new.getName());
                        }
                        else if (ref_db.getName() == null && ref_new.getName() != null) {
                            ref_db.setName(ref_new.getName());
                        }
                        else if (ref_db.getName() != null && ref_new.getName() == null) {
                            ref_db.setName(null);
                        }

                        if (ref_db.getRefsource() != null && ref_new.getRefsource() != null) {
                            if (!ref_db.getRefsource().equals(ref_new.getRefsource())) ref_db.setRefsource(ref_new.getRefsource());
                        }
                        else if (ref_db.getRefsource() == null && ref_new.getRefsource() != null) {
                            ref_db.setRefsource(ref_new.getRefsource());
                        }
                        else if (ref_db.getRefsource() != null && ref_new.getRefsource() == null) {
                            ref_db.setRefsource(null);
                        }

                        if (ref_db.getTags() != null && ref_new.getTags() != null) {
                            if (!ref_db.getTags().equals(ref_new.getTags())) ref_db.setTags(ref_new.getTags());
                        }
                        else if (ref_db.getTags() == null && ref_new.getTags() != null) {
                            ref_db.setTags(ref_new.getTags());
                        }
                        else if (ref_db.getTags() != null && ref_new.getTags() == null) {
                            ref_db.setTags(null);
                        }

                        session.merge(ref_db);
                        refs_to_save.remove(0);
                    }
                    // If there isn't new object to merge with, the old one will be deleted, if its not in the up-to-date CVE object
                    else {
                        db_refs_to_remove.add(cve_db.getReferences().get(i));
                        session.remove(cve_db.getReferences().get(i));
                    }
                }
            }
            cve_db.getReferences().removeAll(db_refs_to_remove);
            // If the new object doesn't have old one to merge with, it will be saved as a new one
            for (ReferenceObject ref_to_save : refs_to_save) {
                ref_to_save.setCve_obj(cve_db);
                session.save(ref_to_save);
            }
        }
        // If new objects are detected, they will be associated and saved into the database
        else if (cve_db.getReferences() == null && cve_obj.getReferences() != null) {
            for (ReferenceObject ref_obj : cve_obj.getReferences()) {
                ref_obj.setCve_obj(cve_db);
                session.save(ref_obj);
            }
        }
        // If deletion of objects is detected, old objects will be deleted from the database
        else if (cve_db.getReferences() != null && cve_obj.getReferences() == null) {
            for (ReferenceObject ref_db : cve_db.getReferences()) {
                ref_db.setCve_obj(null);
                session.remove(ref_db);
            }
        }

        // List for removal of CPE node objects that won't be used because the actualization isn't in them
        List<CPEnodeObject> node_objs_to_remove = new ArrayList<>();
        // List to keep CPE node objects that won't be deleted from database because the actualization isn't in them
        List<CPEnodeObject> node_dbs_not_to_remove = new ArrayList<>();
        // List for ready CPE node objects from file after a little edit that follows
        List<CPEnodeObject> node_objs = new ArrayList<>();
        // Going through CPE node objects from file so that we can make them ready for comparing later on
        for (CPEnodeObject node_obj : cve_obj.getCpe_nodes()) {
            if (node_obj != null) {
                // Making List for CPE to CVE connections, if there won't be any, this attribute will be null
                node_obj.setNode_to_compl(null);
                List<CPEnodeToCPE> connections = new ArrayList<>();
                if (node_obj.getComplex_cpe_objs() != null) {
                    for (CPEcomplexObj complex_cpe_obj : node_obj.getComplex_cpe_objs()) {
                        // Making ID unique if current CPE is complex
                        if (complex_cpe_obj != null) {
                            String basic_cpe_id = complex_cpe_obj.getCpe_id();
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
                            // Making CPE to CVE connections - but only into PC's memory for now
                            // Complex CPE case
                            if (complex_cpe_obj.getVersion_end_excluding() != null || complex_cpe_obj.getVersion_start_excluding() != null ||
                                    complex_cpe_obj.getVersion_end_including() != null || complex_cpe_obj.getVersion_start_including() != null) {
                                CPEnodeToCPE connection = new CPEnodeToCPE((cve_obj.getMeta_data_id()+"#"+complex_cpe_obj.getCpe_id()+"#"+node_obj.getId()), complex_cpe_obj, node_obj, cve_obj.getMeta_data_id(), complex_cpe_obj.getVulnerable(), null);
                                connections.add(connection);
                            }
                            // Basic CPE case
                            else {
                                CPEobject basic_cpe = CPEobject.cpeUriToObject(basic_cpe_id);
                                CPEnodeToCPE connection = new CPEnodeToCPE((cve_obj.getMeta_data_id()+"#"+basic_cpe.getCpe_id()+"#"+node_obj.getId()), null, node_obj, cve_obj.getMeta_data_id(), complex_cpe_obj.getVulnerable(), basic_cpe);
                                connections.add(connection);
                            }
                        }
                    }
                }
                // Putting CVE to CPE connections into current CPE node object and putting this object which is now ready for comparing into List
                node_obj.setNode_to_compl(connections);
                node_objs.add(node_obj);

                // Controlling which objects from database are the same as this object from file
                for (CPEnodeObject node_db : cve_db.getCpe_nodes()) {
                    if (node_db.equals(node_obj)) {
                        node_objs_to_remove.add(node_obj);
                        node_dbs_not_to_remove.add(node_db);
                    }
                }
            }
        }

        // Removing all objects from file that won't be worked with - those that are in database without change
        node_objs.removeAll(node_objs_to_remove);

        // Ensuring parent to child relation by putting parent objects first so that the relation will be made when saving into the database
        List<CPEnodeObject> potential_parent_nodes = new ArrayList<>();
        List<CPEnodeObject> child_nodes = new ArrayList<>();
        for (CPEnodeObject potential_parent : node_objs) {
            if (potential_parent.getParent() == null) {
                potential_parent_nodes.add(potential_parent);
            }
            else {
                child_nodes.add(potential_parent);
            }
        }
        node_objs = potential_parent_nodes;
        node_objs.addAll(child_nodes);

        // Going through CPE node objects of the current CVE object from database
        for (CPEnodeObject node_db : cve_db.getCpe_nodes()) {
            // If the node from database has no edit, it won't be worked with
            if (!node_dbs_not_to_remove.contains(node_db)) {
                // Merging CPE node objects from file with objects from the database until at least one List isn't empty
                if (!node_objs.isEmpty()) {
                    // Taking CPE node object from the database
                    session.evict(node_db);
                    // Taking CPE node object from file for comparing
                    CPEnodeObject node_obj = node_objs.get(0);
                    // Actualizing CPE node attribute if there is any change
                    if (!node_db.getOperator().equals(node_obj.getOperator())) node_db.setOperator(node_obj.getOperator());

                    // Changing Parent relation if needed
                    if (node_db.getParent() != null && node_obj.getParent() != null) {
                        if (!node_db.getParent().equals(node_obj.getParent())) {
                            node_db.setParent(node_obj.getParent());
                        }
                    }
                    else if (node_db.getParent() == null && node_obj.getParent() != null) {
                        node_db.setParent(node_obj.getParent());
                    }
                    else if (node_db.getParent() != null && node_obj.getParent() == null) {
                        node_db.setParent(null);
                    }

                    // Merging CPE node object with the database
                    session.merge(node_db);

                    // Ensuring Child to Parent relations
                    if (node_obj.getChildren() != null) {
                        for (CPEnodeObject child : node_obj.getChildren()) {
                            child.setParent(node_db);
                        }
                    }

                    // Merging of CVE to CPE connection objects
                    if (node_db.getNode_to_compl() != null && node_obj.getNode_to_compl() != null) {
                        // If connections aren't the same, change will be made
                        if (!node_db.getNode_to_compl().equals(node_obj.getNode_to_compl())) {
                            // List for CPE to CVE connection objects of current CPE node object from file
                            List<CPEnodeToCPE> connections_obj = node_obj.getNode_to_compl();

                            // Going through CPE to CVE connections from the database under current CPE node object from the database and removing them
                            for (CPEnodeToCPE connection_db : node_db.getNode_to_compl()) {
                                session.remove(connection_db);
                            }

                            // If there is a CPE to CVE connection from file, it will be simply added into database
                            for (CPEnodeToCPE connection_obj : connections_obj) {
                                // Connection from file has basic CPE object
                                if (connection_obj.getCpe() != null) {
                                    // If the basic CPE object does exist, just the connection will be made
                                    CPEobject cpe_db = (CPEobject) session.get(CPEobject.class, connection_obj.getCpe().getCpe_id());
                                    if (cpe_db != null) {
                                        if (session.get(CPEnodeToCPE.class, (cve_db.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_db.getId())) == null) {
                                            // Creating connection between basic CPE object and CVE
                                            connection_obj = new CPEnodeToCPE((cve_db.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_db.getId()), null, node_db, cve_db.getMeta_data_id(), connection_obj.getVulnerable(), cpe_db);
                                            // Putting CPE node to CPE object into database
                                            session.save(connection_obj);
                                        }
                                    }
                                    // If the basic CPE object doesn't exist, it will be created and put into database
                                    else {
                                        cpe_db = CPEobject.cpeUriToObject(connection_obj.getCpe().getCpe_id());
                                        session.save(cpe_db);
                                        // Creating connection between basic CPE object and CVE
                                        connection_obj = new CPEnodeToCPE((cve_db.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_db.getId()), null, node_db, cve_db.getMeta_data_id(), connection_obj.getVulnerable(), cpe_db);
                                        // Putting CPE node to CPE object into database
                                        session.save(connection_obj);
                                    }
                                }
                                // Connection from file has complex CPE object
                                else if (connection_obj.getCompl_cpe() != null) {
                                    CPEcomplexObj compl_cpe_db = (CPEcomplexObj) session.get(CPEcomplexObj.class, connection_obj.getCompl_cpe().getCpe_id());
                                    CPEcomplexObj compl_cpe_db_com = (CPEcomplexObj) session.get(CPEcomplexObj.class, connection_obj.getCompl_cpe().getCpe_id()+"#"+cve_db.getMeta_data_id());
                                    // Making connection if the complex CPE object already exists
                                    if (compl_cpe_db != null) {
                                        if (session.get(CPEnodeToCPE.class, (cve_db.getMeta_data_id() + "#" + compl_cpe_db.getCpe_id() + "#" + node_db.getId())) == null) {
                                            // Creating connection between CPE and CVE
                                            connection_obj = new CPEnodeToCPE((cve_db.getMeta_data_id() + "#" + compl_cpe_db.getCpe_id() + "#" + node_db.getId()), compl_cpe_db, node_db, cve_db.getMeta_data_id(), connection_obj.getVulnerable(), null);
                                            // Putting CPE node to CPE object into database
                                            session.save(connection_obj);
                                        }
                                    }
                                    else if (compl_cpe_db_com != null) {
                                        if (session.get(CPEnodeToCPE.class, (cve_db.getMeta_data_id() + "#" + compl_cpe_db_com.getCpe_id() + "#" + node_db.getId())) == null) {
                                            // Creating connection between CPE and CVE
                                            connection_obj = new CPEnodeToCPE((cve_db.getMeta_data_id() + "#" + compl_cpe_db_com.getCpe_id() + "#" + node_db.getId()), compl_cpe_db_com, node_db, cve_db.getMeta_data_id(), connection_obj.getVulnerable(), null);
                                            // Putting CPE node to CPE object into database
                                            session.save(connection_obj);
                                        }
                                    }
                                    // Creating new complex CPE object if it doesn't exist
                                    else {
                                        // Creating basic CPE id from complex CPE id
                                        String basic_cpe_id_original = connection_obj.getCompl_cpe().getCpe_id();
                                        String[] cpe_id_array = basic_cpe_id_original.split("#", -1);
                                        // Creating basic CPE object to connect with if it doesn't exist
                                        CPEobject cpe_db = (CPEobject) session.get(CPEobject.class, cpe_id_array[0]);
                                        if (cpe_db == null) {
                                            cpe_db = CPEobject.cpeUriToObject(cpe_id_array[0]);
                                            session.save(cpe_db);
                                        }
                                        connection_obj.getCompl_cpe().setCpe_objs(new ArrayList<>());
                                        // Making connection between complex CPE object and basic CPE object
                                        connection_obj.getCompl_cpe().getCpe_objs().add(cpe_db);
                                        // Ensuring unique ID and putting complex CPE object into database
                                        connection_obj.getCompl_cpe().setCpe_id(connection_obj.getCompl_cpe().getCpe_id()+"#"+cve_db.getMeta_data_id());
                                        session.save(connection_obj.getCompl_cpe());
                                        // Making connection between complex CPE object and CVE object
                                        connection_obj = new CPEnodeToCPE((cve_db.getMeta_data_id()+"#"+connection_obj.getCompl_cpe().getCpe_id()+"#"+node_db.getId()), connection_obj.getCompl_cpe(), node_db, cve_db.getMeta_data_id(), connection_obj.getVulnerable(), null);
                                        // Putting CPE node to CPE object into database
                                        session.save(connection_obj);
                                    }
                                }
                            }
                        }
                    }

                    // If CPE node object from database has no connections and the one from file has, they will be added
                    else if (node_db.getNode_to_compl() == null && node_obj.getNode_to_compl() != null) {
                        for (CPEnodeToCPE node_to_cpe : node_obj.getNode_to_compl()) {
                            // Connection from file has basic CPE object
                            if (node_to_cpe.getCpe() != null) {
                                // If the basic CPE object does exist, just the connection will be made
                                CPEobject cpe_db = (CPEobject) session.get(CPEobject.class, node_to_cpe.getCpe().getCpe_id());
                                if (cpe_db != null) {
                                    if (session.get(CPEnodeToCPE.class, (cve_db.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_db.getId())) == null) {
                                        // Creating connection between basic CPE object and CVE
                                        node_to_cpe = new CPEnodeToCPE((cve_db.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_db.getId()), null, node_db, cve_db.getMeta_data_id(), node_to_cpe.getVulnerable(), cpe_db);
                                        // Putting CPE node to CPE object into database
                                        session.save(node_to_cpe);
                                    }
                                }
                                // If the basic CPE object doesn't exist, it will be created and put into database
                                else {
                                    cpe_db = CPEobject.cpeUriToObject(node_to_cpe.getCpe().getCpe_id());
                                    session.save(cpe_db);
                                    // Creating connection between basic CPE object and CVE
                                    node_to_cpe = new CPEnodeToCPE((cve_db.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_db.getId()), null, node_db, cve_db.getMeta_data_id(), node_to_cpe.getVulnerable(), cpe_db);
                                    // Putting CPE node to CPE object into database
                                    session.save(node_to_cpe);
                                }
                            }
                            // Connection from file has complex CPE object
                            else if (node_to_cpe.getCompl_cpe() != null) {
                                CPEcomplexObj compl_cpe_db = (CPEcomplexObj) session.get(CPEcomplexObj.class, node_to_cpe.getCompl_cpe().getCpe_id());
                                CPEcomplexObj compl_cpe_db_com = (CPEcomplexObj) session.get(CPEcomplexObj.class, node_to_cpe.getCompl_cpe().getCpe_id()+"#"+cve_db.getMeta_data_id());
                                // Making connection if the complex CPE object already exists
                                if (compl_cpe_db != null) {
                                    if (session.get(CPEnodeToCPE.class, (cve_db.getMeta_data_id() + "#" + compl_cpe_db.getCpe_id() + "#" + node_db.getId())) == null) {
                                        // Creating connection between CPE and CVE
                                        node_to_cpe = new CPEnodeToCPE((cve_db.getMeta_data_id() + "#" + compl_cpe_db.getCpe_id() + "#" + node_db.getId()), compl_cpe_db, node_db, cve_db.getMeta_data_id(), node_to_cpe.getVulnerable(), null);
                                        // Putting CPE node to CPE object into database
                                        session.save(node_to_cpe);
                                    }
                                }
                                else if (compl_cpe_db_com != null) {
                                    if (session.get(CPEnodeToCPE.class, (cve_db.getMeta_data_id() + "#" + compl_cpe_db_com.getCpe_id() + "#" + node_db.getId())) == null) {
                                        // Creating connection between CPE and CVE
                                        node_to_cpe = new CPEnodeToCPE((cve_db.getMeta_data_id() + "#" + compl_cpe_db_com.getCpe_id() + "#" + node_db.getId()), compl_cpe_db_com, node_db, cve_db.getMeta_data_id(), node_to_cpe.getVulnerable(), null);
                                        // Putting CPE node to CPE object into database
                                        session.save(node_to_cpe);
                                    }
                                }
                                // Creating new complex CPE object if it doesn't exist
                                else {
                                    // Creating basic CPE id from complex CPE id
                                    String basic_cpe_id_original = node_to_cpe.getCompl_cpe().getCpe_id();
                                    String[] cpe_id_array = basic_cpe_id_original.split("#", -1);
                                    // Creating basic CPE object to connect with if it doesn't exist
                                    CPEobject cpe_db = (CPEobject) session.get(CPEobject.class, cpe_id_array[0]);
                                    if (cpe_db == null) {
                                        cpe_db = CPEobject.cpeUriToObject(cpe_id_array[0]);
                                        session.save(cpe_db);
                                    }
                                    node_to_cpe.getCompl_cpe().setCpe_objs(new ArrayList<>());
                                    // Making connection between complex CPE object and basic CPE object
                                    node_to_cpe.getCompl_cpe().getCpe_objs().add(cpe_db);
                                    // Ensuring unique ID and putting complex CPE object into database
                                    node_to_cpe.getCompl_cpe().setCpe_id(node_to_cpe.getCompl_cpe().getCpe_id()+"#"+cve_db.getMeta_data_id());
                                    session.save(node_to_cpe.getCompl_cpe());
                                    // Making connection between complex CPE object and CVE object
                                    node_to_cpe = new CPEnodeToCPE((cve_db.getMeta_data_id()+"#"+node_to_cpe.getCompl_cpe().getCpe_id()+"#"+node_db.getId()), node_to_cpe.getCompl_cpe(), node_db, cve_db.getMeta_data_id(), node_to_cpe.getVulnerable(), null);
                                    // Putting CPE node to CPE object into database
                                    session.save(node_to_cpe);
                                }
                            }
                        }
                    }
                    // There are connection objects in the database but no connection objets in the file under current CPE node object, those in database will be deleted
                    else if (node_db.getNode_to_compl() != null && node_obj.getNode_to_compl() == null) {
                        for (CPEnodeToCPE node_to_cpe : node_db.getNode_to_compl()) {
                            session.remove(node_to_cpe);
                        }
                    }

                    // Removing CPE node object from file that has been actualized from List
                    node_objs.remove(0);
                }
                // If there is CPE node object in the database that isn't in the file under current CVE object, it will be deleted along with its CVE to CPE connections
                else {
                    for (CPEnodeToCPE node_to_cpe : node_db.getNode_to_compl()) {
                        session.remove(node_to_cpe);
                    }
                    session.remove(node_db);
                }
            }
        }
        // If there is CPE node object in the file that isn't under current CVE object in the database, it will be added
        if (!node_objs.isEmpty()) {
            for (CPEnodeObject node_obj : node_objs) {
                // Making relation between CPE node object and CVE object
                node_obj.setCve_obj(cve_db);
                // Putting CPE node object from file into database
                session.save(node_obj);
                // Going through CPE to CVE connections of current CPE node object and saving them into database
                for (CPEnodeToCPE node_to_cpe : node_obj.getNode_to_compl()) {
                    // Connection from file has basic CPE object
                    if (node_to_cpe.getCpe() != null) {
                        // If the basic CPE object does exist, just the connection will be made
                        CPEobject cpe_db = (CPEobject) session.get(CPEobject.class, node_to_cpe.getCpe().getCpe_id());
                        if (cpe_db != null) {
                            if (session.get(CPEnodeToCPE.class, (cve_db.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId())) == null) {
                                // Creating connection between basic CPE object and CVE
                                node_to_cpe = new CPEnodeToCPE((cve_db.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId()), null, node_obj, cve_db.getMeta_data_id(), node_to_cpe.getVulnerable(), cpe_db);
                                // Putting CPE node to CPE object into database
                                session.save(node_to_cpe);
                            }
                        }
                        // If the basic CPE object doesn't exist, it will be created and put into database
                        else {
                            cpe_db = CPEobject.cpeUriToObject(node_to_cpe.getCpe().getCpe_id());
                            session.save(cpe_db);
                            // Creating connection between basic CPE object and CVE
                            node_to_cpe = new CPEnodeToCPE((cve_db.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId()), null, node_obj, cve_db.getMeta_data_id(), node_to_cpe.getVulnerable(), cpe_db);
                            // Putting CPE node to CPE object into database
                            session.save(node_to_cpe);
                        }
                    }
                    // Connection from file has complex CPE object
                    else if (node_to_cpe.getCompl_cpe() != null) {
                        CPEcomplexObj compl_cpe_db = (CPEcomplexObj) session.get(CPEcomplexObj.class, node_to_cpe.getCompl_cpe().getCpe_id());
                        CPEcomplexObj compl_cpe_db_com = (CPEcomplexObj) session.get(CPEcomplexObj.class, node_to_cpe.getCompl_cpe().getCpe_id()+"#"+cve_db.getMeta_data_id());
                        // Making connection if the complex CPE object already exists
                        if (compl_cpe_db != null) {
                            if (session.get(CPEnodeToCPE.class, (cve_db.getMeta_data_id() + "#" + compl_cpe_db.getCpe_id() + "#" + node_obj.getId())) == null) {
                                // Creating connection between CPE and CVE
                                node_to_cpe = new CPEnodeToCPE((cve_db.getMeta_data_id() + "#" + compl_cpe_db.getCpe_id() + "#" + node_obj.getId()), compl_cpe_db, node_obj, cve_db.getMeta_data_id(), node_to_cpe.getVulnerable(), null);
                                // Putting CPE node to CPE object into database
                                session.save(node_to_cpe);
                            }
                        }
                        else if (compl_cpe_db_com != null) {
                            if (session.get(CPEnodeToCPE.class, (cve_db.getMeta_data_id() + "#" + compl_cpe_db_com.getCpe_id() + "#" + node_obj.getId())) == null) {
                                // Creating connection between CPE and CVE
                                node_to_cpe = new CPEnodeToCPE((cve_db.getMeta_data_id() + "#" + compl_cpe_db_com.getCpe_id() + "#" + node_obj.getId()), compl_cpe_db_com, node_obj, cve_db.getMeta_data_id(), node_to_cpe.getVulnerable(), null);
                                // Putting CPE node to CPE object into database
                                session.save(node_to_cpe);
                            }
                        }
                        // Creating new complex CPE object if it doesn't exist
                        else {
                            // Creating basic CPE id from complex CPE id
                            String basic_cpe_id_original = node_to_cpe.getCompl_cpe().getCpe_id();
                            String[] cpe_id_array = basic_cpe_id_original.split("#", -1);
                            // Creating basic CPE object to connect with if it doesn't exist
                            CPEobject cpe_db = (CPEobject) session.get(CPEobject.class, cpe_id_array[0]);
                            if (cpe_db == null) {
                                cpe_db = CPEobject.cpeUriToObject(cpe_id_array[0]);
                                session.save(cpe_db);
                            }
                            node_to_cpe.getCompl_cpe().setCpe_objs(new ArrayList<>());
                            // Making connection between complex CPE object and basic CPE object
                            node_to_cpe.getCompl_cpe().getCpe_objs().add(cpe_db);
                            // Ensuring unique ID and putting complex CPE object into database
                            node_to_cpe.getCompl_cpe().setCpe_id(node_to_cpe.getCompl_cpe().getCpe_id()+"#"+cve_db.getMeta_data_id());
                            session.save(node_to_cpe.getCompl_cpe());
                            // Making connection between complex CPE object and CVE object
                            node_to_cpe = new CPEnodeToCPE((cve_db.getMeta_data_id()+"#"+node_to_cpe.getCompl_cpe().getCpe_id()+"#"+node_obj.getId()), node_to_cpe.getCompl_cpe(), node_obj, cve_db.getMeta_data_id(), node_to_cpe.getVulnerable(), null);
                            // Putting CPE node to CPE object into database
                            session.save(node_to_cpe);
                        }
                    }
                }
            }
        }
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
        return Objects.equals(meta_data_id, cvEobject.meta_data_id) && Objects.equals(data_type, cvEobject.data_type) && Objects.equals(data_format, cvEobject.data_format) && Objects.equals(data_version, cvEobject.data_version) && Objects.equals(meta_data_assigner, cvEobject.meta_data_assigner) && Objects.equals(cwe, cvEobject.cwe) && Objects.equals(references, cvEobject.references) && Objects.equals(descriptions, cvEobject.descriptions) && Objects.equals(cve_data_version, cvEobject.cve_data_version) && Objects.equals(cpe_nodes, cvEobject.cpe_nodes) && Objects.equals(cvss_v2, cvEobject.cvss_v2) && Objects.equals(cvss_v3, cvEobject.cvss_v3) && Objects.equals(cvss_v2_base_score, cvEobject.cvss_v2_base_score) && Objects.equals(cvss_v3_base_score, cvEobject.cvss_v3_base_score) && Objects.equals(published_date, cvEobject.published_date) && Objects.equals(last_modified_date, cvEobject.last_modified_date);
    }

    @Override
    public int hashCode() {
        return Objects.hash(meta_data_id, data_type, data_format, data_version, meta_data_assigner, cwe, references, descriptions, cve_data_version, cpe_nodes, cvss_v2, cvss_v3, cvss_v2_base_score, cvss_v3_base_score, published_date, last_modified_date);
    }
}
