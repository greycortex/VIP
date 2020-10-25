import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;

/**
 * This class represents a CAPEC attack pattern object (---)
 * <p>
 * It can parse CAPEC attack pattern objects from given XML file that they are in
 * <p>
 * It uses DOM XML parser
 * <p>
 * It can also create a CAPEC attack pattern object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CAPECobject {

    protected String capec_id;
    protected String capec_name;
    protected String capec_abstraction;
    protected String capec_status;
    protected String description;
    protected ArrayList<String> rel_cwe_ids;
    protected ArrayList<String> mitigations;
    protected ArrayList<CWEnoteObj> notes;
    protected ArrayList<CWEtaxMapObj> tax_maps;
    protected ArrayList<CWEalterTermObj> alter_terms;
    protected ArrayList<CWEextRefRefObj> ext_ref_refs;
    protected ArrayList<CWEconseqObj> consequences;

    /**
     * Copies constructor
     *
     * @param capec_id                ID of a specific attack pattern (CAPEC)
     * @param capec_name              name of a specific attack pattern (CAPEC)
     * @param capec_abstraction       abstraction attribute of a specific attack pattern (CAPEC)
     * @param capec_status            status of a specific attack pattern (CAPEC)
     * @param description             description of a specific attack pattern (CAPEC)
     * @param rel_cwe_ids             IDs of relating CWE weaknesses for a specific attack pattern (CAPEC)
     * @param mitigations             mitigation attributes of a specific attack pattern (CAPEC)
     * @param notes                   note objects of a specific CAPEC object
     * @param tax_maps                taxonomy mapping objects of a specific CAPEC object
     * @param alter_terms             alternate term objects of a specific CAPEC object
     * @param ext_ref_refs            external reference reference objects of a specific CAPEC object
     * @param consequences            consequence objects of a specific CAPEC object
     */
    public CAPECobject(String capec_id, String capec_name, String capec_abstraction, String capec_status, String description,
                       ArrayList<String> rel_cwe_ids, ArrayList<String> mitigations, ArrayList<CWEnoteObj> notes,
                       ArrayList<CWEtaxMapObj> tax_maps, ArrayList<CWEalterTermObj> alter_terms, ArrayList<CWEextRefRefObj> ext_ref_refs,
                       ArrayList<CWEconseqObj> consequences){

        this.capec_id = capec_id;
        this.capec_name = capec_name;
        this.capec_abstraction = capec_abstraction;
        this.capec_status = capec_status;
        this.description = description;
        this.rel_cwe_ids = rel_cwe_ids;
        this.mitigations = mitigations;
        this.notes = notes;
        this.tax_maps = tax_maps;
        this.alter_terms = alter_terms;
        this.ext_ref_refs = ext_ref_refs;
        this.consequences = consequences;

    }

    /**
     * This method's purpose is to parse and create an ArrayList of CAPEC attack pattern objects from given XML file
     * which contains them
     * <p>
     * It uses DOM XML parser
     * <p>
     * It goes through file that contains latest list of CAPEC attack patterns,
     * parses them and returns them in an ArrayList
     *
     * @return ArrayList of CAPEC attack pattern objects from given XML file
     */
    public static ArrayList<CAPECobject> CAPECfileToArrayList(){
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();

        ArrayList<CAPECobject> capec_objs = new ArrayList<>(); // empty ArrayList which will be filled with CAPEC attack pattern objects later on

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
                            ArrayList<String> pattern_rel_cwe_ids = new ArrayList<>(); // relating CWE IDs
                            ArrayList<String> pattern_mitigs = new ArrayList<>(); // mitigation attributes
                            ArrayList<CWEnoteObj> pattern_notes = new ArrayList<>(); // note objects
                            ArrayList<CWEtaxMapObj> pattern_tax_maps = new ArrayList<>(); // taxonomy mapping objects
                            ArrayList<CWEalterTermObj> pattern_alter_terms = new ArrayList<>(); // alternate term objects
                            ArrayList<CWEextRefRefObj> pattern_ext_ref_refs = new ArrayList<>(); // external reference reference objects
                            ArrayList<CWEconseqObj> pattern_consequences = new ArrayList<>(); // consequence objects



                            NamedNodeMap attr = nodes_att_patterns.item(z).getAttributes();
                            String pattern_id = attr.getNamedItem("ID").getNodeValue(); // getting ID attribute
                            String pattern_name = attr.getNamedItem("Name").getNodeValue(); // getting name attribute
                            String pattern_abstraction = attr.getNamedItem("Abstraction").getNodeValue(); // getting abstraction attribute
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
                                            ArrayList<String> conseq_scopes = new ArrayList<>();
                                            ArrayList<String> conseq_impacts = new ArrayList<>();
                                            ArrayList<String> conseq_notes = new ArrayList<>();
                                            ArrayList<String> conseq_likelihoods = new ArrayList<>();

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

                                } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Related_Weaknesses")){
                                    NodeList rel_cwe_nodes = attack_patt_child_nodes.item(y).getChildNodes();

                                    for (int t = 0; t < rel_cwe_nodes.getLength(); t++) {
                                        if (rel_cwe_nodes.item(t).getNodeName().equals("Related_Weakness")){
                                            NamedNodeMap pattern_rel_cwe_attr = rel_cwe_nodes.item(t).getAttributes();
                                            String rel_cwe_id = pattern_rel_cwe_attr.getNamedItem("CWE_ID").getNodeValue(); // getting related weakness ID (CWE)
                                            pattern_rel_cwe_ids.add(rel_cwe_id);
                                        }
                                    }

                                } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Likelihood_Of_Attack")){


                                } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Typical_Severity")){

                                } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Related_Attack_Patterns")) {

                                } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Execution_Flow")){

                                } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Prerequisites")){

                                } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Skills_Required")){

                                } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Example_Instances")){

                                } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Resources_Required")){

                                } else if (attack_patt_child_nodes.item(y).getNodeName().equals("Indicators")){

                                }
                            }

                            capec_objs.add(new CAPECobject(pattern_id, pattern_name, pattern_abstraction, pattern_status, pattern_description,
                                    pattern_rel_cwe_ids, pattern_mitigs, pattern_notes, pattern_tax_maps, pattern_alter_terms,
                                    pattern_ext_ref_refs, pattern_consequences)); // creating new CAPEC attack pattern object
                        }
                    }
                }
            }
        } catch (SAXException | IOException | ParserConfigurationException ex) {
            ex.printStackTrace();
        }

        return capec_objs; // returning ArrayList filled with CAPEC attack pattern objects
    }

    /**
     * This method's purpose is to create a CAPEC object from given parameters and return it
     *
     * @return CAPEC object
     */
    public static CAPECobject getInstance(String capec_id, String capec_name, String capec_abstraction, String capec_status, String description,
                                          ArrayList<String> rel_cwe_ids, ArrayList<String> mitigations, ArrayList<CWEnoteObj> notes,
                                          ArrayList<CWEtaxMapObj> tax_maps, ArrayList<CWEalterTermObj> alter_terms, ArrayList<CWEextRefRefObj> ext_ref_refs,
                                          ArrayList<CWEconseqObj> consequences) {

        return new CAPECobject(capec_id, capec_name, capec_abstraction, capec_status, description, rel_cwe_ids, mitigations,
                               notes, tax_maps, alter_terms, ext_ref_refs, consequences);
    }

    @Override
    public String toString() {
        return "CAPECobject{" +
                "capec_id='" + capec_id + '\'' +
                ", capec_name='" + capec_name + '\'' +
                ", capec_abstraction='" + capec_abstraction + '\'' +
                ", capec_status='" + capec_status + '\'' +
                ", description='" + description + '\'' +
                ", rel_cwe_ids=" + rel_cwe_ids +
                ", mitigations=" + mitigations +
                ", notes=" + notes +
                ", tax_maps=" + tax_maps +
                ", alter_terms=" + alter_terms +
                ", ext_ref_refs=" + ext_ref_refs +
                ", consequences=" + consequences +
                '}';
    }
}
