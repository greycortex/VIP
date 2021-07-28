package mitre.capec;

import mitre.cwe.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.persistence.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a CAPEC attack pattern object (CAPEC ID, name, abstraction attribute, status, ...)
 * <p>
 * It can parse CAPEC attack pattern objects from given XML file
 * <p>
 * It uses DOM XML parser
 * <p>
 * It can also create a CAPEC attack pattern object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "capec")
@Table(name="capec", schema = "mitre")
public class CAPECobject {

    public CAPECobject() { } // default constructor

    @Id
    @Column(unique = true, name = "id")
    protected String capec_id;
    protected String capec_name;
    protected String capec_abstraction;
    protected String capec_status;
    protected String description;
    protected String attack_likelihood;
    protected String typical_severity;
    @ManyToMany
    @CollectionTable(name = "cwe_capec", schema = "mitre")
    protected List<CWEobject> cwe;
    @Column(name = "mitigation")
    @CollectionTable(name = "mitigations", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> mitigations;
    @Column(name = "prerequisite")
    @CollectionTable(name = "prerequisites", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> prerequisites;
    @Column(name = "example")
    @CollectionTable(name = "examples", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> examples;
    @Column(name = "resource")
    @CollectionTable(name = "resources", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> resources;
    @Column(name = "indicator")
    @CollectionTable(name = "indicators", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> indicators;
    @OneToMany(mappedBy = "capec")
    protected List<CWEnoteObj> notes;
    @OneToMany(mappedBy = "capec")
    protected List<CWEtaxMapObj> tax_maps;
    @OneToMany(mappedBy = "capec")
    protected List<CWEalterTermObj> alter_terms;
    @OneToMany(mappedBy = "capec")
    protected List<CWEextRefRefObj> ext_ref_refs;
    @OneToMany(mappedBy = "capec")
    protected List<CWEconseqObj> consequences;
    @OneToMany(mappedBy = "capec")
    protected List<CAPECrelationObj> related_patterns;
    @OneToMany(mappedBy = "capec")
    protected List<CAPECattStepObj> attack_steps;
    @OneToMany(mappedBy = "capec")
    protected List<CAPECskillObj> skills_required;

    /**
     * Copies constructor
     *
     * @param capec_id                ID of a specific attack pattern (CAPEC)
     * @param capec_name              name of a specific attack pattern (CAPEC)
     * @param capec_abstraction       abstraction attribute of a specific attack pattern (CAPEC)
     * @param capec_status            status of a specific attack pattern (CAPEC)
     * @param description             description of a specific attack pattern (CAPEC)
     * @param attack_likelihood       likelihood of attack attribute of a specific attack pattern (CAPEC)
     * @param typical_severity        typical severity attribute of a specific attack pattern (CAPEC)
     * @param cwe                     relating CWE weaknesses for a specific attack pattern (CAPEC)
     * @param mitigations             mitigation attributes of a specific attack pattern (CAPEC)
     * @param prerequisites           prerequisite attributes of a specific attack pattern (CAPEC)
     * @param examples                example attributes of a specific attack pattern (CAPEC)
     * @param resources               resources required for a specific attack pattern (CAPEC)
     * @param indicators              indicators of a specific attack pattern (CAPEC)
     * @param notes                   note objects of a specific CAPEC object
     * @param tax_maps                taxonomy mapping objects of a specific CAPEC object
     * @param alter_terms             alternate term objects of a specific CAPEC object
     * @param ext_ref_refs            external reference reference objects of a specific CAPEC object
     * @param consequences            consequence objects of a specific CAPEC object
     * @param related_patterns        related CAPEC attack patterns - relation objects
     * @param attack_steps            attack step objects (execution flow) of a specific CAPEC object
     * @param skills_required         skills required attribute of a specific CAPEC object - skill objects
     */
    public CAPECobject(String capec_id, String capec_name, String capec_abstraction, String capec_status, String description,
                       String attack_likelihood, String typical_severity, List<CWEobject> cwe, List<String> mitigations,
                       List<CWEnoteObj> notes, List<CWEtaxMapObj> tax_maps, List<CWEalterTermObj> alter_terms,
                       List<CWEextRefRefObj> ext_ref_refs, List<CWEconseqObj> consequences,
                       List<CAPECattStepObj> attack_steps, List<CAPECrelationObj> related_patterns,
                       List<String> prerequisites, List<CAPECskillObj> skills_required, List<String> examples,
                       List<String> resources, List<String> indicators){

        this.capec_id = capec_id;
        this.capec_name = capec_name;
        this.capec_abstraction = capec_abstraction;
        this.capec_status = capec_status;
        this.description = description;
        this.attack_likelihood = attack_likelihood;
        this.typical_severity = typical_severity;
        this.cwe = cwe;
        this.mitigations = mitigations;
        this.prerequisites = prerequisites;
        this.examples = examples;
        this.resources = resources;
        this.indicators = indicators;
        this.notes = notes;
        this.tax_maps = tax_maps;
        this.alter_terms = alter_terms;
        this.ext_ref_refs = ext_ref_refs;
        this.consequences = consequences;
        this.related_patterns = related_patterns;
        this.attack_steps = attack_steps;
        this.skills_required = skills_required;

    }

    public String getCapec_id() {
        return capec_id;
    }

    /**
     * This method's purpose is to parse and create a List of CAPEC attack pattern objects from given XML file
     * which contains them
     * <p>
     * It uses DOM XML parser
     * <p>
     * It goes through file that contains latest list of CAPEC attack patterns,
     * parses them and returns them in a List
     *
     * @return List of CAPEC attack pattern objects from given XML file
     */
    public static List<CAPECobject> CAPECfileToArrayList(){
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();

        List<CAPECobject> capec_objs = new ArrayList<>(); // empty List which will be filled with CAPEC attack pattern objects later on

        try {
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document document = builder.parse(new FileInputStream("exclude/capec_latest.xml")); // https://capec.mitre.org/data/xml/capec_latest.xml
            Element doc_element = document.getDocumentElement();
            NodeList nodes = doc_element.getChildNodes();

            for (int i = 0; i < nodes.getLength(); i++) {
                if (nodes.item(i).getNodeName().equals("Attack_Patterns")) {
                    NodeList nodes_att_patterns = nodes.item(i).getChildNodes();
                    for (int z = 0; z < nodes_att_patterns.getLength(); z++) {
                        if (nodes_att_patterns.item(z).getNodeName().equals("Attack_Pattern")) {

                            String pattern_description = null; // description
                            String pattern_attack_likelihood = null; // likelihood of attack attribute
                            String pattern_typical_severity = null; // typical severity attribute
                            List<CWEobject> pattern_rel_cwe_ids = new ArrayList<>(); // relating CWEs
                            List<String> pattern_mitigs = new ArrayList<>(); // mitigation attributes
                            List<String> pattern_prerequisites = new ArrayList<>(); // prerequisite attributes
                            List<String> pattern_examples = new ArrayList<>(); // example attributes
                            List<String> pattern_resources = new ArrayList<>(); // resource attributes
                            List<String> pattern_indicators = new ArrayList<>(); // indicator attributes
                            List<CWEnoteObj> pattern_notes = new ArrayList<>(); // note objects
                            List<CWEtaxMapObj> pattern_tax_maps = new ArrayList<>(); // taxonomy mapping objects
                            List<CWEalterTermObj> pattern_alter_terms = new ArrayList<>(); // alternate term objects
                            List<CWEextRefRefObj> pattern_ext_ref_refs = new ArrayList<>(); // external reference reference objects
                            List<CWEconseqObj> pattern_consequences = new ArrayList<>(); // consequence objects
                            List<CAPECrelationObj> pattern_rel_patterns = new ArrayList<>(); // related attack patterns
                            List<CAPECattStepObj> pattern_attack_steps = new ArrayList<>(); // attack step objects - execution flow
                            List<CAPECskillObj> pattern_skills_required = new ArrayList<>(); // skills required - CAPEC skill objects

                            NamedNodeMap attr = nodes_att_patterns.item(z).getAttributes();
                            String pattern_id = attr.getNamedItem("ID").getNodeValue(); // getting ID attribute
                            String pattern_name = attr.getNamedItem("Name").getNodeValue(); // getting name attribute
                            String pattern_abstraction = attr.getNamedItem("Abstraction").getNodeValue(); // getting abstraction attribute

                            if (attr.getNamedItem("Status").getNodeValue().equals("Deprecated"))
                                ; // If this attack pattern is deprecated it won't be returned
                            else{
                                String pattern_status = attr.getNamedItem("Status").getNodeValue(); // getting status attribute

                                NodeList attack_patt_child_nodes = nodes_att_patterns.item(z).getChildNodes();
                                for (int y = 0; y < attack_patt_child_nodes.getLength(); y++) {
                                    if (attack_patt_child_nodes.item(y).getNodeName().equals("Description")) {
                                        pattern_description = attack_patt_child_nodes.item(y).getTextContent(); // getting description attribute

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Notes")){
                                        NodeList notes_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int r = 0; r < notes_nodes.getLength(); r++) {
                                            if (notes_nodes.item(r).getNodeName().equals("Note")) {
                                                NamedNodeMap note_type_attr = notes_nodes.item(r).getAttributes();
                                                String note_type = note_type_attr.getNamedItem("Type").getNodeValue(); // getting type attribute - note object
                                                String note_note = notes_nodes.item(r).getTextContent(); // getting content of the note - note object
                                                pattern_notes.add(new CWEnoteObj(note_type, note_note)); // creating note object
                                            }
                                        }

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Taxonomy_Mappings")){
                                        NodeList tax_map_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int c = 0; c < tax_map_nodes.getLength(); c++) {
                                            if (tax_map_nodes.item(c).getNodeName().equals("Taxonomy_Mapping")) {
                                                NamedNodeMap tax_map_attr = tax_map_nodes.item(c).getAttributes();
                                                NodeList tax_map_specific_nodes = tax_map_nodes.item(c).getChildNodes();

                                                String tax_name = tax_map_attr.getNamedItem("Taxonomy_Name").getNodeValue(); // getting name attribute - taxonomy mapping object
                                                String tax_entry_name = null;
                                                String tax_entry_id = null;
                                                String tax_map_fit = null;

                                                for (int v = 0; v < tax_map_specific_nodes.getLength(); v++) {
                                                    if (tax_map_specific_nodes.item(v).getNodeName().equals("Entry_Name")) {
                                                        tax_entry_name = tax_map_specific_nodes.item(v).getTextContent(); // getting entry name attribute - taxonomy mapping object
                                                    } else if (tax_map_specific_nodes.item(v).getNodeName().equals("Entry_ID")) {
                                                        tax_entry_id = tax_map_specific_nodes.item(v).getTextContent(); // getting entry ID attribute - taxonomy mapping object
                                                    } else if (tax_map_specific_nodes.item(v).getNodeName().equals("Mapping_Fit")) {
                                                        tax_map_fit = tax_map_specific_nodes.item(v).getTextContent(); // getting mapping fit attribute - taxonomy mapping object
                                                    }
                                                }

                                                pattern_tax_maps.add(new CWEtaxMapObj(tax_name, tax_entry_name, tax_entry_id, tax_map_fit)); // creating taxonomy mapping object
                                            }
                                        }

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Alternate_Terms")){
                                        NodeList alter_term_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int q = 0; q < alter_term_nodes.getLength(); q++) {
                                            if (alter_term_nodes.item(q).getNodeName().equals("Alternate_Term")) {
                                                NodeList alter_term_specific_nodes = alter_term_nodes.item(q).getChildNodes();
                                                String alternate_term_term = null;
                                                String alternate_term_description = null;

                                                for (int e = 0; e < alter_term_specific_nodes.getLength(); e++) {
                                                    if (alter_term_specific_nodes.item(e).getNodeName().equals("Term")) {
                                                        alternate_term_term = alter_term_specific_nodes.item(e).getTextContent(); // getting term attribute - alternate term object
                                                    } else if (alter_term_specific_nodes.item(e).getNodeName().equals("Description")) {
                                                        alternate_term_description = alter_term_specific_nodes.item(e).getTextContent(); // getting description attribute - alternate term object
                                                    }
                                                }

                                                pattern_alter_terms.add(new CWEalterTermObj(alternate_term_term, alternate_term_description)); // creating alternate term object
                                            }
                                        }

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("References")){
                                        NodeList ext_ref_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int w = 0; w < ext_ref_nodes.getLength(); w++) {
                                            if (ext_ref_nodes.item(w).getNodeName().equals("Reference")) {
                                                NamedNodeMap ext_ref_attr = ext_ref_nodes.item(w).getAttributes();
                                                String ext_ref_id = ext_ref_attr.getNamedItem("External_Reference_ID").getNodeValue(); // getting ID attribute - external reference reference object

                                                String ext_ref_section = null;
                                                if (ext_ref_attr.getNamedItem("Section") != null) {
                                                    ext_ref_section = ext_ref_attr.getNamedItem("Section").getNodeValue(); // getting section attribute - external reference reference object
                                                }

                                                pattern_ext_ref_refs.add(new CWEextRefRefObj(ext_ref_id, ext_ref_section)); // creating external reference reference object
                                            }
                                        }

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Consequences")){
                                        NodeList conseq_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int j = 0; j < conseq_nodes.getLength(); j++) {
                                            if (conseq_nodes.item(j).getNodeName().equals("Consequence")) {
                                                List<String> conseq_scopes = new ArrayList<>();
                                                List<String> conseq_impacts = new ArrayList<>();
                                                List<String> conseq_notes = new ArrayList<>();
                                                List<String> conseq_likelihoods = new ArrayList<>();

                                                NodeList conseq_specific_nodes = conseq_nodes.item(j).getChildNodes();
                                                for (int o = 0; o < conseq_specific_nodes.getLength(); o++) {
                                                    if (conseq_specific_nodes.item(o).getNodeName().equals("Scope")) { // getting scope attribute - consequence object
                                                        conseq_scopes.add(conseq_specific_nodes.item(o).getTextContent());
                                                    } else if (conseq_specific_nodes.item(o).getNodeName().equals("Impact")) { // getting impact attribute - consequence object
                                                        conseq_impacts.add(conseq_specific_nodes.item(o).getTextContent());
                                                    } else if (conseq_specific_nodes.item(o).getNodeName().equals("Note")) { // getting note attribute - consequence object
                                                        conseq_notes.add(conseq_specific_nodes.item(o).getTextContent());
                                                    } else if (conseq_specific_nodes.item(o).getNodeName().equals("Likelihood")) { // getting likelihood attribute - consequence object
                                                        conseq_likelihoods.add(conseq_specific_nodes.item(o).getTextContent());
                                                    }
                                                }

                                                pattern_consequences.add(new CWEconseqObj(conseq_scopes, conseq_impacts,
                                                        conseq_notes, conseq_likelihoods)); // creating consequence object
                                            }
                                        }

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Mitigations")){
                                        NodeList mitig_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int g = 0; g < mitig_nodes.getLength(); g++) {
                                            if (mitig_nodes.item(g).getNodeName().equals("Mitigation")){
                                                pattern_mitigs.add(mitig_nodes.item(g).getTextContent()); // getting mitigation attribute
                                            }
                                        }

                                    //} else if (attack_patt_child_nodes.item(y).getNodeName().equals("Related_Weaknesses")){
                                    //    NodeList rel_cwe_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        //for (int t = 0; t < rel_cwe_nodes.getLength(); t++) {
                                        //    if (rel_cwe_nodes.item(t).getNodeName().equals("Related_Weakness")){
                                        //        NamedNodeMap pattern_rel_cwe_attr = rel_cwe_nodes.item(t).getAttributes();
                                        //        String rel_cwe_id = pattern_rel_cwe_attr.getNamedItem("CWE_ID").getNodeValue(); // getting related weakness ID (CWE)
                                        //        pattern_rel_cwe_ids.add(rel_cwe_id);
                                        //    }
                                        //}

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Likelihood_Of_Attack")){
                                        pattern_attack_likelihood = attack_patt_child_nodes.item(y).getTextContent(); // getting likelihood of attack attribute

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Typical_Severity")){
                                        pattern_typical_severity = attack_patt_child_nodes.item(y).getTextContent(); // getting typical severity attribute

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Related_Attack_Patterns")) {
                                        NodeList rel_pattern_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int m = 0; m < rel_pattern_nodes.getLength(); m++) {
                                            if (rel_pattern_nodes.item(m).getNodeName().equals("Related_Attack_Pattern")){
                                                NamedNodeMap pattern_rel_pattern_attr = rel_pattern_nodes.item(m).getAttributes();

                                                String rel_pattern_id = pattern_rel_pattern_attr.getNamedItem("CAPEC_ID").getNodeValue(); // getting related attack pattern (CAPEC) ID
                                                String rel_pattern_nature = pattern_rel_pattern_attr.getNamedItem("Nature").getNodeValue(); // getting nature attribute

                                                List<String> exclude_ids = new ArrayList<>();
                                                NodeList rel_pattern_pattern_nodes = rel_pattern_nodes.item(m).getChildNodes();
                                                for (int n = 0; n < rel_pattern_pattern_nodes.getLength(); n++) {
                                                    if (rel_pattern_pattern_nodes.item(n).getNodeName().equals("Exclude_Related")){
                                                        NamedNodeMap exclude_attr = rel_pattern_pattern_nodes.item(n).getAttributes();
                                                        exclude_ids.add(exclude_attr.getNamedItem("Exclude_ID").getNodeValue()); // getting exclude ID
                                                    }
                                                }

                                                pattern_rel_patterns.add(new CAPECrelationObj(rel_pattern_nature, rel_pattern_id, exclude_ids)); // creating CAPEC relation object
                                            }
                                        }

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Execution_Flow")){
                                        NodeList exec_flow_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int v = 0; v < exec_flow_nodes.getLength(); v++) {
                                            if (exec_flow_nodes.item(v).getNodeName().equals("Attack_Step")) {
                                                NodeList exec_flow_spec_at_step = exec_flow_nodes.item(v).getChildNodes();

                                                List<String> att_step_techs = new ArrayList<>();
                                                String att_step_spec = null;
                                                String att_phase_spec = null;
                                                String att_descr_spec = null;

                                                for (int t = 0; t < exec_flow_spec_at_step.getLength(); t++) {
                                                    if (exec_flow_spec_at_step.item(t).getNodeName().equals("Step")) {
                                                        att_step_spec = exec_flow_spec_at_step.item(t).getTextContent(); // getting step attribute - attack step object

                                                    } else if (exec_flow_spec_at_step.item(t).getNodeName().equals("Phase")) {
                                                        att_phase_spec = exec_flow_spec_at_step.item(t).getTextContent(); // getting phase attribute - attack step object

                                                    } else if (exec_flow_spec_at_step.item(t).getNodeName().equals("Description")) {
                                                        att_descr_spec = exec_flow_spec_at_step.item(t).getTextContent(); // getting description attribute - attack step object

                                                    } else if (exec_flow_spec_at_step.item(t).getNodeName().equals("Technique")) {
                                                        att_step_techs.add(exec_flow_spec_at_step.item(t).getTextContent()); // getting technique attribute - attack step object

                                                    }
                                                }

                                                pattern_attack_steps.add(new CAPECattStepObj(att_step_spec, att_phase_spec, att_descr_spec, att_step_techs)); // creating attack step object
                                            }
                                        }

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Prerequisites")){
                                        NodeList prerequisite_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int j = 0; j < prerequisite_nodes.getLength(); j++) {
                                            if (prerequisite_nodes.item(j).getNodeName().equals("Prerequisite")){
                                                pattern_prerequisites.add(prerequisite_nodes.item(j).getTextContent()); // getting prerequisite attribute
                                            }
                                        }

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Skills_Required")){
                                        NodeList skills_required_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int g = 0; g < skills_required_nodes.getLength(); g++) {
                                            if (skills_required_nodes.item(g).getNodeName().equals("Skill")){
                                                NamedNodeMap skill_attr = skills_required_nodes.item(g).getAttributes();
                                                String skill_level = skill_attr.getNamedItem("Level").getNodeValue(); // getting level attribute - CAPEC skill object
                                                String skill_content = skills_required_nodes.item(g).getTextContent(); // getting skill info - CAPEC skill object

                                                pattern_skills_required.add(new CAPECskillObj(skill_level, skill_content)); // creating CAPEC skill object
                                            }
                                        }

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Example_Instances")){
                                        NodeList example_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int j = 0; j < example_nodes.getLength(); j++) {
                                            if (example_nodes.item(j).getNodeName().equals("Example")){
                                                pattern_examples.add(example_nodes.item(j).getTextContent()); // getting example attribute
                                            }
                                        }

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Resources_Required")){
                                        NodeList resources_req_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int j = 0; j < resources_req_nodes.getLength(); j++) {
                                            if (resources_req_nodes.item(j).getNodeName().equals("Resource")){
                                                pattern_resources.add(resources_req_nodes.item(j).getTextContent()); // getting resource attribute
                                            }
                                        }

                                    } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Indicators")){
                                        NodeList indicator_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                        for (int j = 0; j < indicator_nodes.getLength(); j++) {
                                            if (indicator_nodes.item(j).getNodeName().equals("Indicator")){
                                                pattern_indicators.add(indicator_nodes.item(j).getTextContent()); // getting indicator attribute
                                            }
                                        }
                                    }
                                }

                                capec_objs.add(new CAPECobject(pattern_id, pattern_name, pattern_abstraction, pattern_status, pattern_description,
                                        pattern_attack_likelihood, pattern_typical_severity, pattern_rel_cwe_ids, pattern_mitigs, pattern_notes,
                                        pattern_tax_maps, pattern_alter_terms, pattern_ext_ref_refs, pattern_consequences, pattern_attack_steps,
                                        pattern_rel_patterns, pattern_prerequisites, pattern_skills_required, pattern_examples, pattern_resources,
                                        pattern_indicators)); // creating new CAPEC attack pattern object
                            }
                        }
                    }
                }
            }
        } catch (SAXException | IOException | ParserConfigurationException ex) {
            ex.printStackTrace();
        }

        return capec_objs; // returning List filled with CAPEC attack pattern objects
    }

    ///**
    // * This method's purpose is to create a CAPEC attack pattern object from given parameters and return it
    // *
    // * @return CAPEC attack pattern object
    // */
    //public static CAPECobject getInstance(String capec_id, String capec_name, String capec_abstraction, String capec_status, String description,
    //                                      String attack_likelihood, String typical_severity, List<String> rel_cwe,
    //                                      List<String> mitigations, List<CWEnoteObj> notes, List<CWEtaxMapObj> tax_maps,
    //                                      List<CWEalterTermObj> alter_terms, List<CWEextRefRefObj> ext_ref_refs,
    //                                      List<CWEconseqObj> consequences, List<CAPECattStepObj> attack_steps,
    //                                      List<CAPECrelationObj> related_patterns, List<String> prerequisites,
    //                                      List<CAPECskillObj> skills_required, List<String> examples,
    //                                      List<String> resources, List<String> indicators) {

    //    return new CAPECobject(capec_id, capec_name, capec_abstraction, capec_status, description, attack_likelihood,
    //                           typical_severity, rel_cwe, mitigations, notes, tax_maps, alter_terms, ext_ref_refs, consequences,
    //                           attack_steps, related_patterns, prerequisites, skills_required, examples, resources, indicators);
    //}

    @Override
    public String toString() {
        return "CAPECobject{" +
                "capec_id='" + capec_id + '\'' +
                ", capec_name='" + capec_name + '\'' +
                ", capec_abstraction='" + capec_abstraction + '\'' +
                ", capec_status='" + capec_status + '\'' +
                ", description='" + description + '\'' +
                ", attack_likelihood='" + attack_likelihood + '\'' +
                ", typical_severity='" + typical_severity + '\'' +
                ", cwe=" + cwe +
                ", mitigations=" + mitigations +
                ", notes=" + notes +
                ", tax_maps=" + tax_maps +
                ", alter_terms=" + alter_terms +
                ", ext_ref_refs=" + ext_ref_refs +
                ", consequences=" + consequences +
                ", attack_steps=" + attack_steps +
                ", related_patterns=" + related_patterns +
                ", prerequisites=" + prerequisites +
                ", skills_required=" + skills_required +
                ", examples=" + examples +
                ", resources=" + resources +
                ", indicators=" + indicators +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CAPECobject)) return false;
        CAPECobject that = (CAPECobject) o;
        return Objects.equals(capec_id, that.capec_id) && Objects.equals(capec_name, that.capec_name) && Objects.equals(capec_abstraction, that.capec_abstraction) && Objects.equals(capec_status, that.capec_status) && Objects.equals(description, that.description) && Objects.equals(attack_likelihood, that.attack_likelihood) && Objects.equals(typical_severity, that.typical_severity) && Objects.equals(cwe, that.cwe) && Objects.equals(mitigations, that.mitigations) && Objects.equals(prerequisites, that.prerequisites) && Objects.equals(examples, that.examples) && Objects.equals(resources, that.resources) && Objects.equals(indicators, that.indicators) && Objects.equals(notes, that.notes) && Objects.equals(tax_maps, that.tax_maps) && Objects.equals(alter_terms, that.alter_terms) && Objects.equals(ext_ref_refs, that.ext_ref_refs) && Objects.equals(consequences, that.consequences) && Objects.equals(related_patterns, that.related_patterns) && Objects.equals(attack_steps, that.attack_steps) && Objects.equals(skills_required, that.skills_required);
    }

    @Override
    public int hashCode() {
        return Objects.hash(capec_id, capec_name, capec_abstraction, capec_status, description, attack_likelihood, typical_severity, cwe, mitigations, prerequisites, examples, resources, indicators, notes, tax_maps, alter_terms, ext_ref_refs, consequences, related_patterns, attack_steps, skills_required);
    }
}
