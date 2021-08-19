package mitre.cwe;

import mitre.capec.CAPECobject;
import mitre.cve.CVEobject;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.service.ServiceRegistry;
import org.xml.sax.SAXException;
import org.w3c.dom.*;

import javax.persistence.*;
import javax.persistence.Entity;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.*;

/**
 * This class represents a CWE object (CWE code (ID), name of weakness, abstraction attribute, structure attribute, ...)
 * <p>
 * It can parse CWE weakness objects from given XML file
 * <p>
 * Objects can be put into database
 * <p>
 * It also can create a CWE object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "cwe")
@Table(name="cwe", schema = "mitre")
public class CWEobject implements Serializable {

    public CWEobject() {} // default constructor

    @Id
    @Column(unique = true, name = "id")
    protected String code_id;
    protected String name;
    protected String abstraction;
    protected String structure;
    protected String status;
    @Column(length = 8191)
    protected String description;
    @Column(length = 8191)
    protected String ext_description;
    protected String exploit_likelihood;
    @OneToMany(mappedBy = "cwe")
    protected List<CWErelationObj> relations;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEapplPlatfObj> appl_platform_objs;
    @Column(name = "bg_detail", length = 8191)
    @CollectionTable(name = "cwe_bg_details", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> bg_details;
    @ManyToMany
    @CollectionTable(name = "cwe_capec", schema = "mitre")
    protected List<CAPECobject> capec;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEnoteObj> notes;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEintrModesObj> intr_modes;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEconseqObj> consequences;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEalterTermObj> alter_terms;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEextRefRefObj> ext_ref_refs;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEtaxMapObj> tax_maps;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEpotMitObj> pot_mits;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEweakOrdObj> weak_ords;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEdemExObj> dem_examples;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEobsExObj> obs_examples;
    @OneToMany(mappedBy = "cwe")
    protected List<CWEdetMethObj> det_meths;
    @Column(name = "affected_resource")
    @CollectionTable(name = "cwe_affected_resources", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> affected_resources;
    @Column(name = "functional_area")
    @CollectionTable(name = "cwe_functional_areas", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> functional_areas;
    @ManyToMany(mappedBy = "cwe")
    protected List<CVEobject> cve;
    @OneToMany(mappedBy = "related_cwe")
    protected List<CWErelationObj> relations_related;


    /**
     * Copies constructor
     *
     * @param code_id             CWE code (ID) of a specific CWE
     * @param name                name of a specific weakness (CWE)
     * @param abstraction         information about abstraction of a specific CWE
     * @param structure           information about structure of a specific CWE
     * @param status              information about status of a specific CWE
     * @param description         description of a specific weakness (CWE)
     * @param ext_description     extended description (descriptions) of a specific weakness (CWE)
     * @param exploit_likelihood  likelihood of exploit attribute
     * @param relations           CWE relation objects
     * @param appl_platform_objs  CWE applicable platform objects
     * @param bg_details          background details attributes
     * @param notes               note objects (type, content of the note)
     * @param intr_modes          introduction (from modes of introduction) objects
     * @param consequences        consequence objects
     * @param alter_terms         alternate terms objects
     * @param ext_ref_refs        external reference reference objects
     * @param tax_maps            taxonomy mapping objects
     * @param pot_mits            potential mitigations objects
     * @param weak_ords           weakness ordinality objects
     * @param dem_examples        demonstrative example objects
     * @param obs_examples        observed example objects
     * @param det_meths           detection method objects
     * @param capec               related CAPEC (attack pattern) objects
     * @param affected_resources  affected resource attributes
     * @param functional_areas    funtional area attributes
     */
    public CWEobject(String code_id, String name, String abstraction, String structure, String status, String description,
                     String ext_description, String exploit_likelihood, List<CWErelationObj> relations, List<CWEapplPlatfObj> appl_platform_objs,
                     List<String> bg_details, List<CWEnoteObj> notes, List<CWEintrModesObj> intr_modes,
                     List<CWEconseqObj> consequences, List<CWEalterTermObj> alter_terms, List<CWEextRefRefObj> ext_ref_refs,
                     List<CWEtaxMapObj> tax_maps, List<CWEpotMitObj> pot_mits, List<CWEweakOrdObj> weak_ords,
                     List<CWEdemExObj> dem_examples, List<CWEobsExObj> obs_examples, List<CWEdetMethObj> det_meths,
                     List<CAPECobject> capec, List<String> affected_resources, List<String> functional_areas) {

        this.code_id = code_id;
        this.name = name;
        this.abstraction = abstraction;
        this.structure = structure;
        this.status = status;
        this.description = description;
        this.ext_description = ext_description;
        this.exploit_likelihood = exploit_likelihood;
        this.relations = relations;
        this.appl_platform_objs = appl_platform_objs;
        this.bg_details = bg_details;
        this.notes = notes;
        this.intr_modes = intr_modes;
        this.consequences = consequences;
        this.alter_terms = alter_terms;
        this.ext_ref_refs = ext_ref_refs;
        this.tax_maps = tax_maps;
        this.pot_mits = pot_mits;
        this.weak_ords = weak_ords;
        this.dem_examples = dem_examples;
        this.obs_examples = obs_examples;
        this.det_meths = det_meths;
        this.capec = capec;
        this.affected_resources = affected_resources;
        this.functional_areas = functional_areas;

    }

    public void setCapec(List<CAPECobject> capec) {
        this.capec = capec;
    }

    public String getCode_id() {
        return code_id;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public List<CWErelationObj> getRelations() {
        return relations;
    }

    public List<CWEapplPlatfObj> getAppl_platform_objs() {
        return appl_platform_objs;
    }

    public List<CAPECobject> getCapec() {
        return capec;
    }

    public List<CWEnoteObj> getNotes() {
        return notes;
    }

    public List<CWEintrModesObj> getIntr_modes() {
        return intr_modes;
    }

    public List<CWEconseqObj> getConsequences() {
        return consequences;
    }

    public List<CWEalterTermObj> getAlter_terms() {
        return alter_terms;
    }

    public List<CWEextRefRefObj> getExt_ref_refs() {
        return ext_ref_refs;
    }

    public List<CWEtaxMapObj> getTax_maps() {
        return tax_maps;
    }

    public List<CWEpotMitObj> getPot_mits() {
        return pot_mits;
    }

    public List<CWEweakOrdObj> getWeak_ords() {
        return weak_ords;
    }

    public List<CWEdemExObj> getDem_examples() {
        return dem_examples;
    }

    public List<CWEobsExObj> getObs_examples() {
        return obs_examples;
    }

    public List<CWEdetMethObj> getDet_meths() {
        return det_meths;
    }

    public List<CVEobject> getCve() {
        return cve;
    }

    /**
     * This method's purpose is to parse and create a List of CWE weakness objects from given XML file
     * which contains them and to make connections with the right CAPEC objects
     * <p>
     * It uses DOM XML parser
     * <p>
     * It goes through file that contains latest list of CWE weaknesses,
     * parses them and returns them in a List
     *
     * @param cwe_file path to .xml file with CWE data
     * @param capec_objs existing CAPEC objects for search of the relating ones
     * @param ext_refs existing CWE External Reference objects for search of the relating ones
     * @return List of CWE weakness objects from given XML file
     */
    public static List<CWEobject> CWEfileToArraylist(String cwe_file, List<CAPECobject> capec_objs, List<CWEextRefObj> ext_refs) {
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();

        List<CWEobject> cwe_objs = new ArrayList<>(); // empty List which will be filled with CWE weakness objects later on

        try {
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document document = builder.parse(new FileInputStream(cwe_file)); // https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
            Element doc_element = document.getDocumentElement();
            NodeList nodes = doc_element.getChildNodes();

            for (int i = 0; i < nodes.getLength(); i++) {
                if (nodes.item(i).getNodeName().equals("Weaknesses")) {
                    NodeList nodes_weaknesses = nodes.item(i).getChildNodes();
                    for (int z = 0; z < nodes_weaknesses.getLength(); z++) {
                        if (nodes_weaknesses.item(z).getNodeName().equals("Weakness")) {

                            String cwe_name = null; // name
                            String cwe_abstraction = null; // abstraction
                            String cwe_structure = null; // structure
                            String cwe_status = null; // status
                            String cwe_description = null; // description
                            String cwe_ext_description = null; // extended description
                            String cwe_exploit_likelihood = null; // likelihood of exploit
                            List<CWErelationObj> cwe_relations = new ArrayList<>(); // CWE relation objects
                            List<CWEapplPlatfObj> cwe_appl_platform_objs = new ArrayList<>(); // CWE applicable platform objects
                            List<String> cwe_bg_details = new ArrayList<>(); // bg_details attribute
                            List<CAPECobject> cwe_rel_attack_patterns = new ArrayList<>(); // CAPEC ID attributes
                            List<String> cwe_affected_resources = new ArrayList<>(); // affected resource attributes
                            List<String> cwe_functional_areas = new ArrayList<>(); // functional area attributes
                            List<CWEnoteObj> cwe_notes = new ArrayList<>(); // notes
                            List<CWEintrModesObj> cwe_intr_modes = new ArrayList<>(); // introduction (from modes of introduction) objects
                            List<CWEconseqObj> cwe_consequences = new ArrayList<>(); // consequence objects
                            List<CWEalterTermObj> cwe_alter_terms = new ArrayList<>(); // alternate term objects
                            List<CWEextRefRefObj> cwe_ext_ref_refs = new ArrayList<>(); // external reference reference objects
                            List<CWEtaxMapObj> cwe_tax_maps = new ArrayList<>(); // taxonomy mapping objects
                            List<CWEpotMitObj> cwe_pot_mits = new ArrayList<>(); // potential mitigation objects
                            List<CWEweakOrdObj> cwe_weak_ords = new ArrayList<>(); // weakness ordinality objects
                            List<CWEdemExObj> cwe_dem_examples = new ArrayList<>(); // demonstrative example objects
                            List<CWEobsExObj> cwe_obs_examples = new ArrayList<>(); // observed example objects
                            List<CWEdetMethObj> cwe_det_meths = new ArrayList<>(); // detection method objects

                            NamedNodeMap attr = nodes_weaknesses.item(z).getAttributes();
                            cwe_status = attr.getNamedItem("Status").getNodeValue(); // getting status attribute

                            // if the CWE is deprecated, it won't be added into the returned list
                            if (!cwe_status.equals("Deprecated")) {
                                String cwe_id = attr.getNamedItem("ID").getNodeValue(); // getting CWE id
                                cwe_name = attr.getNamedItem("Name").getNodeValue(); // getting name attribute
                                cwe_abstraction = attr.getNamedItem("Abstraction").getNodeValue(); // getting abstraction attribute
                                cwe_structure = attr.getNamedItem("Structure").getNodeValue(); // getting structure attribute

                                NodeList cwe_child_nodes = nodes_weaknesses.item(z).getChildNodes();

                                for (int y = 0; y < cwe_child_nodes.getLength(); y++) {
                                    if (cwe_child_nodes.item(y).getNodeName().equals("Description")) {
                                        cwe_description = cwe_child_nodes.item(y).getTextContent(); // getting description attribute

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Extended_Description")) {
                                        cwe_ext_description = cwe_child_nodes.item(y).getTextContent(); // getting extended description attribute

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Related_Weaknesses")) {
                                        NodeList related_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int k = 0; k < related_nodes.getLength(); k++) {
                                            if (related_nodes.item(k).getNodeName().equals("Related_Weakness")) {
                                                NamedNodeMap related_attr = related_nodes.item(k).getAttributes();
                                                String nature = related_attr.getNamedItem("Nature").getNodeValue(); // getting nature attribute - CWE relation object
                                                String related_cwe_id = related_attr.getNamedItem("CWE_ID").getNodeValue(); // getting related CWE code (ID) - CWE relation object
                                                String view_id = related_attr.getNamedItem("View_ID").getNodeValue(); // getting view_id attribute - CWE relation object
                                                if (related_attr.getNamedItem("Ordinal") != null) {
                                                    String ordinal = related_attr.getNamedItem("Ordinal").getNodeValue(); // getting ordinal attribute - CWE relation objects
                                                    cwe_relations.add(new CWErelationObj(nature, related_cwe_id, view_id, ordinal)); // creating CWE relation object

                                                } else
                                                    cwe_relations.add(new CWErelationObj(nature, related_cwe_id, view_id, null)); // creating CWE relation object
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Applicable_Platforms")) {
                                        NodeList appl_platf = cwe_child_nodes.item(y).getChildNodes();

                                        for (int g = 0; g < appl_platf.getLength(); g++) {
                                            NamedNodeMap appl_platf_attr = appl_platf.item(g).getAttributes();

                                            if (appl_platf_attr != null) {
                                                String appl_platf_name = null;
                                                String appl_platf_class = null;

                                                if (appl_platf_attr.getNamedItem("Name") != null) {
                                                    appl_platf_name = appl_platf_attr.getNamedItem("Name").getNodeValue(); // getting name attribute - CWE applicable platform object
                                                } else if (appl_platf_attr.getNamedItem("Class") != null) {
                                                    appl_platf_class = appl_platf_attr.getNamedItem("Class").getNodeValue(); // getting class attribute - CWE applicable platform object
                                                }

                                                String appl_platf_prevalence = appl_platf_attr.getNamedItem("Prevalence").getNodeValue(); // getting prevalence attribute - CWE applicable platform object

                                                if (appl_platf.item(g).getNodeName().equals("Language")) {
                                                    // getting type attribute - CWE applicable platform object; creating CWE applicable platform object
                                                    cwe_appl_platform_objs.add(new CWEapplPlatfObj("Language", appl_platf_class, appl_platf_name, appl_platf_prevalence));
                                                } else if (appl_platf.item(g).getNodeName().equals("Architecture")) {
                                                    // getting type attribute - CWE applicable platform object; creating CWE applicable platform object
                                                    cwe_appl_platform_objs.add(new CWEapplPlatfObj("Architecture", appl_platf_class, appl_platf_name, appl_platf_prevalence));
                                                } else if (appl_platf.item(g).getNodeName().equals("Technology")) {
                                                    // getting type attribute - CWE applicable platform object; creating CWE applicable platform object
                                                    cwe_appl_platform_objs.add(new CWEapplPlatfObj("Technology", appl_platf_class, appl_platf_name, appl_platf_prevalence));
                                                } else if (appl_platf.item(g).getNodeName().equals("Operating_System")) {
                                                    // getting type attribute - CWE applicable platform object; creating CWE applicable platform object
                                                    cwe_appl_platform_objs.add(new CWEapplPlatfObj("Operating_System", appl_platf_class, appl_platf_name, appl_platf_prevalence));
                                                }
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Background_Details")) {
                                        NodeList bg_details_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int t = 0; t < bg_details_nodes.getLength(); t++) {
                                            if (bg_details_nodes.item(t).getNodeName().equals("Background_Detail")) {
                                                cwe_bg_details.add(bg_details_nodes.item(t).getTextContent()); // background detail attribute - bg_details attribute
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Modes_Of_Introduction")) {
                                        NodeList intr_modes_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int h = 0; h < intr_modes_nodes.getLength(); h++) {
                                            if (intr_modes_nodes.item(h).getNodeName().equals("Introduction")) {
                                                NodeList intr_specific_nodes = intr_modes_nodes.item(h).getChildNodes();
                                                String intr_phase = null; // phase attribute - introduction (from modes of introduction) object
                                                String intr_note = null; // note attribute - introduction (from modes of introduction) object

                                                for (int u = 0; u < intr_specific_nodes.getLength(); u++) {
                                                    if (intr_specific_nodes.item(u).getNodeName().equals("Phase")) {
                                                        intr_phase = intr_specific_nodes.item(u).getTextContent(); // getting phase attribute - introduction (from modes of introduction) object
                                                    } else if (intr_specific_nodes.item(u).getNodeName().equals("Note")) {
                                                        intr_note = intr_specific_nodes.item(u).getTextContent(); // getting note attribute - introduction (from modes of introduction) object
                                                    }
                                                }

                                                cwe_intr_modes.add(new CWEintrModesObj(intr_phase, intr_note)); // creating introduction (from modes of introduction) object
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Likelihood_Of_Exploit")) {
                                        cwe_exploit_likelihood = cwe_child_nodes.item(y).getTextContent(); // getting likelihood of exploit attribute

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Common_Consequences")) {
                                        NodeList conseq_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int j = 0; j < conseq_nodes.getLength(); j++) {
                                            if (conseq_nodes.item(j).getNodeName().equals("Consequence")) {
                                                List<String> cwe_conseq_scopes = new ArrayList<>();
                                                List<String> cwe_conseq_impacts = new ArrayList<>();
                                                List<String> cwe_conseq_notes = new ArrayList<>();
                                                List<String> cwe_conseq_likelihoods = new ArrayList<>();

                                                NodeList conseq_specific_nodes = conseq_nodes.item(j).getChildNodes();
                                                for (int o = 0; o < conseq_specific_nodes.getLength(); o++) {
                                                    if (conseq_specific_nodes.item(o).getNodeName().equals("Scope")) { // getting scope attribute - consequence object
                                                        cwe_conseq_scopes.add(conseq_specific_nodes.item(o).getTextContent());
                                                    } else if (conseq_specific_nodes.item(o).getNodeName().equals("Impact")) { // getting impact attribute - consequence object
                                                        cwe_conseq_impacts.add(conseq_specific_nodes.item(o).getTextContent());
                                                    } else if (conseq_specific_nodes.item(o).getNodeName().equals("Note")) { // getting note attribute - consequence object
                                                        cwe_conseq_notes.add(conseq_specific_nodes.item(o).getTextContent());
                                                    } else if (conseq_specific_nodes.item(o).getNodeName().equals("Likelihood")) { // getting likelihood attribute - consequence object
                                                        cwe_conseq_likelihoods.add(conseq_specific_nodes.item(o).getTextContent());
                                                    }
                                                }

                                                cwe_consequences.add(new CWEconseqObj(cwe_conseq_scopes, cwe_conseq_impacts,
                                                        cwe_conseq_notes, cwe_conseq_likelihoods)); // creating consequence object
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Alternate_Terms")) {
                                        NodeList alter_term_nodes = cwe_child_nodes.item(y).getChildNodes();

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

                                                cwe_alter_terms.add(new CWEalterTermObj(alternate_term_term, alternate_term_description)); // creating alternate term object
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Notes")) {
                                        NodeList notes_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int r = 0; r < notes_nodes.getLength(); r++) {
                                            if (notes_nodes.item(r).getNodeName().equals("Note")) {
                                                NamedNodeMap note_type_attr = notes_nodes.item(r).getAttributes();
                                                String cwe_note_type = note_type_attr.getNamedItem("Type").getNodeValue(); // getting type attribute - note object
                                                String cwe_note_note = notes_nodes.item(r).getTextContent(); // getting content of the note - note object
                                                cwe_notes.add(new CWEnoteObj(cwe_note_type, cwe_note_note)); // creating note object
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("References")) {
                                        NodeList ext_ref_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int w = 0; w < ext_ref_nodes.getLength(); w++) {
                                            if (ext_ref_nodes.item(w).getNodeName().equals("Reference")) {
                                                NamedNodeMap ext_ref_attr = ext_ref_nodes.item(w).getAttributes();
                                                String cwe_ext_ref_id = "CWE-" + ext_ref_attr.getNamedItem("External_Reference_ID").getNodeValue(); // getting ID attribute - external reference reference object

                                                String cwe_ext_ref_section = null;
                                                if (ext_ref_attr.getNamedItem("Section") != null) {
                                                    cwe_ext_ref_section = ext_ref_attr.getNamedItem("Section").getNodeValue(); // getting section attribute - external reference reference object
                                                }

                                                CWEextRefRefObj ext_ref_ref_local = new CWEextRefRefObj(null, cwe_ext_ref_section); // Creating external reference reference object
                                                for (CWEextRefObj ext_ref_local : ext_refs) {
                                                    if (ext_ref_local.getReference_id().equals(cwe_ext_ref_id)) {
                                                        ext_ref_ref_local.setExt_ref(ext_ref_local); // Making connection between External Reference object and External Reference Reference object
                                                    }
                                                }

                                                cwe_ext_ref_refs.add(ext_ref_ref_local);
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Taxonomy_Mappings")) {
                                        NodeList tax_map_nodes = cwe_child_nodes.item(y).getChildNodes();

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

                                                cwe_tax_maps.add(new CWEtaxMapObj(tax_name, tax_entry_name, tax_entry_id, tax_map_fit)); // creating taxonomy mapping object
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Potential_Mitigations")) {
                                        NodeList pot_mit_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int c = 0; c < pot_mit_nodes.getLength(); c++) {
                                            if (pot_mit_nodes.item(c).getNodeName().equals("Mitigation")) {
                                                NodeList pot_mit_specific_nodes = pot_mit_nodes.item(c).getChildNodes();

                                                String pot_mit_id = null;
                                                NamedNodeMap pot_mit_attr = pot_mit_nodes.item(c).getAttributes();
                                                if (pot_mit_attr.getNamedItem("Mitigation_ID") != null) {
                                                    pot_mit_id = pot_mit_attr.getNamedItem("Mitigation_ID").getNodeValue(); // getting mitigation id attribute - potential mitigation object
                                                }

                                                List<String> pot_mit_phases = new ArrayList<>();
                                                String pot_mit_strat = null;
                                                String pot_mit_descr = null;
                                                String pot_mit_effect = null;
                                                String pot_mit_effect_notes = null;

                                                for (int g = 0; g < pot_mit_specific_nodes.getLength(); g++) {
                                                    if (pot_mit_specific_nodes.item(g).getNodeName().equals("Phase")) {
                                                        pot_mit_phases.add(pot_mit_specific_nodes.item(g).getTextContent()); // getting phase attributes - potential mitigation object
                                                    } else if (pot_mit_specific_nodes.item(g).getNodeName().equals("Strategy")) {
                                                        pot_mit_strat = pot_mit_specific_nodes.item(g).getTextContent(); // getting strategy attribute - potential mitigation object
                                                    } else if (pot_mit_specific_nodes.item(g).getNodeName().equals("Description")) {
                                                        pot_mit_descr = pot_mit_specific_nodes.item(g).getTextContent(); // getting description attribute - potential mitigation object
                                                    } else if (pot_mit_specific_nodes.item(g).getNodeName().equals("Effectiveness")) {
                                                        pot_mit_effect = pot_mit_specific_nodes.item(g).getTextContent(); // getting effectiveness attribute - potential mitigation object
                                                    } else if (pot_mit_specific_nodes.item(g).getNodeName().equals("Effectiveness_Notes")) {
                                                        pot_mit_effect_notes = pot_mit_specific_nodes.item(g).getTextContent(); // getting effectiveness notes attribute - potential mitigation object
                                                    }
                                                }

                                                cwe_pot_mits.add(new CWEpotMitObj(pot_mit_id, pot_mit_phases, pot_mit_strat, pot_mit_descr,
                                                        pot_mit_effect, pot_mit_effect_notes)); // creating potential mitigation object
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Weakness_Ordinalities")) {
                                        NodeList weak_ord_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int n = 0; n < weak_ord_nodes.getLength(); n++) {
                                            if (weak_ord_nodes.item(n).getNodeName().equals("Weakness_Ordinality")) {
                                                NodeList weak_ord_specific_nodes = weak_ord_nodes.item(n).getChildNodes();

                                                String weak_ord_ord = null;
                                                String weak_ord_descr = null;

                                                for (int r = 0; r < weak_ord_specific_nodes.getLength(); r++) {
                                                    if (weak_ord_specific_nodes.item(r).getNodeName().equals("Ordinality")) {
                                                        weak_ord_ord = weak_ord_specific_nodes.item(r).getTextContent(); // getting ordinality attribute - weakness ordinality object
                                                    } else if (weak_ord_specific_nodes.item(r).getNodeName().equals("Description")) {
                                                        weak_ord_descr = weak_ord_specific_nodes.item(r).getTextContent(); // getting description attribute - weakness ordinality object
                                                    }
                                                }

                                                cwe_weak_ords.add(new CWEweakOrdObj(weak_ord_ord, weak_ord_descr)); // creating weakness ordinality object
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Demonstrative_Examples")) {
                                        NodeList dem_example_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int d = 0; d < dem_example_nodes.getLength(); d++) {

                                            String dem_intro_text = null;
                                            List<CWEexampCodeObj> dem_ex_ex_codes = new ArrayList<>();
                                            List<String> dem_ex_body_texts = new ArrayList<>();
                                            List<CWEextRefRefObj> dem_ex_ext_ref_refs = new ArrayList<>();

                                            if (dem_example_nodes.item(d).getNodeName().equals("Demonstrative_Example")) {
                                                NodeList dem_example_specific_nodes = dem_example_nodes.item(d).getChildNodes();

                                                for (int p = 0; p < dem_example_specific_nodes.getLength(); p++) {
                                                    if (dem_example_specific_nodes.item(p).getNodeName().equals("Intro_Text")) {
                                                        dem_intro_text = dem_example_specific_nodes.item(p).getTextContent(); // getting intro text attribute - demonstrative example object

                                                    } else if (dem_example_specific_nodes.item(p).getNodeName().equals("Example_Code")) {
                                                        NamedNodeMap examp_code_attr = dem_example_specific_nodes.item(p).getAttributes();
                                                        String ex_code_language = null;

                                                        String ex_code_nature = examp_code_attr.getNamedItem("Nature").getNodeValue(); // getting nature attribute - example code object - demonstrative example object
                                                        if (examp_code_attr.getNamedItem("Language") != null) {
                                                            ex_code_language = examp_code_attr.getNamedItem("Language").getNodeValue(); // getting language attribute - example code object - demonstrative example object
                                                        }
                                                        String ex_code_content = dem_example_specific_nodes.item(p).getTextContent(); // getting content - example code object - demonstrative example object

                                                        dem_ex_ex_codes.add(new CWEexampCodeObj(ex_code_nature, ex_code_language, ex_code_content)); // creating example code object - demonstrative example object

                                                    } else if (dem_example_specific_nodes.item(p).getNodeName().equals("Body_Text")) {
                                                        dem_ex_body_texts.add(dem_example_specific_nodes.item(p).getTextContent()); // getting body text attribute - demonstrative example object

                                                    } else if (dem_example_specific_nodes.item(p).getNodeName().equals("References")) {
                                                        NodeList ext_ref_ref_nodes = dem_example_specific_nodes.item(p).getChildNodes();

                                                        for (int w = 0; w < ext_ref_ref_nodes.getLength(); w++) {
                                                            if (ext_ref_ref_nodes.item(w).getNodeName().equals("Reference")) {
                                                                NamedNodeMap ext_ref_attr = ext_ref_ref_nodes.item(w).getAttributes();
                                                                String dem_ext_ref_id = "CWE-" + ext_ref_attr.getNamedItem("External_Reference_ID").getNodeValue(); // getting ID attribute - external reference reference object - demonstrative example object

                                                                String dem_ext_ref_section = null;
                                                                if (ext_ref_attr.getNamedItem("Section") != null) {
                                                                    dem_ext_ref_section = ext_ref_attr.getNamedItem("Section").getNodeValue(); // getting section attribute - external reference reference object - demonstrative example object
                                                                }

                                                                CWEextRefRefObj ext_ref_ref_local = new CWEextRefRefObj(null, dem_ext_ref_section); // Creating external reference reference object
                                                                for (CWEextRefObj ext_ref_local : ext_refs) {
                                                                    if (ext_ref_local.getReference_id().equals(dem_ext_ref_id)) {
                                                                        ext_ref_ref_local.setExt_ref(ext_ref_local); // Making connection between External Reference object and External Reference Reference object
                                                                    }
                                                                }

                                                                dem_ex_ext_ref_refs.add(ext_ref_ref_local); // creating external reference reference object - demonstrative example object
                                                            }
                                                        }
                                                    }
                                                }

                                                cwe_dem_examples.add(new CWEdemExObj(dem_intro_text, dem_ex_ex_codes, dem_ex_body_texts, dem_ex_ext_ref_refs)); // creating demonstrative example object
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Observed_Examples")) {
                                        NodeList obs_ex_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int d = 0; d < obs_ex_nodes.getLength(); d++) {
                                            if (obs_ex_nodes.item(d).getNodeName().equals("Observed_Example")) {
                                                NodeList obs_ex_specific_nodes = obs_ex_nodes.item(d).getChildNodes();

                                                String obs_ex_ref = null;
                                                String obs_ex_descr = null;
                                                String obs_ex_link = null;

                                                for (int w = 0; w < obs_ex_specific_nodes.getLength(); w++) {
                                                    if (obs_ex_specific_nodes.item(w).getNodeName().equals("Reference")) {
                                                        obs_ex_ref = obs_ex_specific_nodes.item(w).getTextContent(); // getting reference attribute - observed example object
                                                    } else if (obs_ex_specific_nodes.item(w).getNodeName().equals("Description")) {
                                                        obs_ex_descr = obs_ex_specific_nodes.item(w).getTextContent(); // getting description attribute - observed example object
                                                    } else if (obs_ex_specific_nodes.item(w).getNodeName().equals("Link")) {
                                                        obs_ex_link = obs_ex_specific_nodes.item(w).getTextContent(); // getting link attribute - observed example object
                                                    }
                                                }

                                                cwe_obs_examples.add(new CWEobsExObj(obs_ex_ref, obs_ex_descr, obs_ex_link)); // creating observed example object
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Detection_Methods")) {
                                        NodeList det_meth_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int d = 0; d < det_meth_nodes.getLength(); d++) {
                                            if (det_meth_nodes.item(d).getNodeName().equals("Detection_Method")) {
                                                NodeList det_meth_specific_nodes = det_meth_nodes.item(d).getChildNodes();

                                                String det_meth_meth = null;
                                                String det_meth_descr = null;
                                                String det_meth_effect = null;
                                                String det_meth_effect_note = null;
                                                String det_meth_id = null;

                                                NamedNodeMap det_meth_attr = det_meth_nodes.item(d).getAttributes();
                                                if (det_meth_attr.getNamedItem("Detection_Method_ID") != null) {
                                                    det_meth_id = det_meth_attr.getNamedItem("Detection_Method_ID").getNodeValue(); // getting detection method id attribute - detection method object
                                                }

                                                for (int g = 0; g < det_meth_specific_nodes.getLength(); g++) {
                                                    if (det_meth_specific_nodes.item(g).getNodeName().equals("Method")) {
                                                        det_meth_meth = det_meth_specific_nodes.item(g).getTextContent(); // getting method attribute - detection method object
                                                    } else if (det_meth_specific_nodes.item(g).getNodeName().equals("Description")) {
                                                        det_meth_descr = det_meth_specific_nodes.item(g).getTextContent(); // getting description attribute - detection method object
                                                    } else if (det_meth_specific_nodes.item(g).getNodeName().equals("Effectiveness")) {
                                                        det_meth_effect = det_meth_specific_nodes.item(g).getTextContent(); // getting effectiveness attribute - detection method object
                                                    } else if (det_meth_specific_nodes.item(g).getNodeName().equals("Effectiveness_Notes")) {
                                                        det_meth_effect_note = det_meth_specific_nodes.item(g).getTextContent(); // getting effectiveness notes attribute - detection method object
                                                    }
                                                }

                                                cwe_det_meths.add(new CWEdetMethObj(det_meth_id, det_meth_meth, det_meth_descr,
                                                        det_meth_effect, det_meth_effect_note)); // creating detection method object
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Related_Attack_Patterns")) {
                                        NodeList rel_attack_patt_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int d = 0; d < rel_attack_patt_nodes.getLength(); d++) {
                                            if (rel_attack_patt_nodes.item(d).getNodeName().equals("Related_Attack_Pattern")) {
                                                NamedNodeMap rel_attack_patt = rel_attack_patt_nodes.item(d).getAttributes();
                                                String rel_attack_patt_id = rel_attack_patt.getNamedItem("CAPEC_ID").getNodeValue(); // getting CAPEC ID attribute
                                                for (int p = 0; p < capec_objs.size(); p++){
                                                    if (capec_objs.get(p).getCapec_id().equals(rel_attack_patt_id)){
                                                        cwe_rel_attack_patterns.add(capec_objs.get(p));
                                                    }
                                                }
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Affected_Resources")) {
                                        NodeList affect_res_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int d = 0; d < affect_res_nodes.getLength(); d++) {
                                            if (affect_res_nodes.item(d).getNodeName().equals("Affected_Resource")) {
                                                String affected_resource = affect_res_nodes.item(d).getTextContent(); // getting affected resource attribute
                                                cwe_affected_resources.add(affected_resource);
                                            }
                                        }

                                    } else if (cwe_child_nodes.item(y).getNodeName().equals("Functional_Areas")) {
                                        NodeList func_areas_nodes = cwe_child_nodes.item(y).getChildNodes();

                                        for (int d = 0; d < func_areas_nodes.getLength(); d++) {
                                            if (func_areas_nodes.item(d).getNodeName().equals("Functional_Area")) {
                                                String functional_area = func_areas_nodes.item(d).getTextContent(); // getting functional area attribute
                                                cwe_functional_areas.add(functional_area);
                                            }
                                        }
                                    }
                                }

                                cwe_objs.add(new CWEobject(cwe_id, cwe_name, cwe_abstraction, cwe_structure, cwe_status, cwe_description, cwe_ext_description,
                                        cwe_exploit_likelihood, cwe_relations, cwe_appl_platform_objs, cwe_bg_details, cwe_notes, cwe_intr_modes,
                                        cwe_consequences, cwe_alter_terms, cwe_ext_ref_refs, cwe_tax_maps, cwe_pot_mits, cwe_weak_ords,
                                        cwe_dem_examples, cwe_obs_examples, cwe_det_meths, cwe_rel_attack_patterns, cwe_affected_resources,
                                        cwe_functional_areas));
                            }
                        }
                    }
                }
            }
        } catch (SAXException | IOException | ParserConfigurationException ex) {
            ex.printStackTrace();
        }

        return cwe_objs;
    }

    /**
     * This method's purpose is to put all CWE objects and their relations into database
     *
     * @param cwe_objs      List of all parsed CWE objects
     * @param sf            object needed to get hibernate Session Factory and to work with database
     */
    public static void CWEintoDatabase(List<CWEobject> cwe_objs, SessionFactory sf) {

        // Openning session, beginning transaction
        Session sessionc = sf.openSession();
        Transaction txv = sessionc.beginTransaction();

        // Putting CWE objects into database
        for (CWEobject cwe : cwe_objs) {
            if (sessionc.get(CWEobject.class, cwe.getCode_id()) == null) {
                // Creating List for CAPEC connecting
                List<CAPECobject> capecs_to_add = new ArrayList<>();
                // Connecting related CAPEC objects
                for (CAPECobject capec : cwe.getCapec()) {
                    // Connection between CAPEC and CWE will be made
                    CAPECobject capec_to_add = (CAPECobject) sessionc.get(CAPECobject.class, capec.getCapec_id());
                    if (capec_to_add != null) {
                        capecs_to_add.add(capec_to_add);
                    }
                }
                // CAPEC connecting
                cwe.setCapec(new ArrayList<>());
                cwe.getCapec().addAll(capecs_to_add);
                // Putting CWE object into database
                sessionc.save(cwe);
            }
        }
        // Committing transaction
        txv.commit();
        // Beginning transaction
        txv = sessionc.beginTransaction();

        for (CWEobject cwe : cwe_objs) {
            if (sessionc.get(CWEobject.class, cwe.getCode_id()) != null) {
                // Putting CWE relation objects into database
                for (CWErelationObj rel: cwe.getRelations()) {
                    CWEobject related_cwe = (CWEobject) sessionc.get(CWEobject.class, rel.getRelated_cwe_id());
                    if (related_cwe != null) {
                        rel.setRelated_cwe(related_cwe);
                        rel.setCwe(cwe);
                        sessionc.save(rel);
                    }
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
                    if (ext_ref_ref.getExt_ref() != null) {
                        CWEextRefObj ext_ref_to_set = (CWEextRefObj) sessionc.get(CWEextRefObj.class, ext_ref_ref.getExt_ref().getReference_id());
                        ext_ref_ref.setExt_ref(ext_ref_to_set);
                        ext_ref_ref.setCwe(cwe);
                        sessionc.save(ext_ref_ref);
                    }
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
                        if (ext_ref_ref.getExt_ref() != null) {
                            CWEextRefObj ext_ref_to_set = (CWEextRefObj) sessionc.get(CWEextRefObj.class, ext_ref_ref.getExt_ref().getReference_id());
                            ext_ref_ref.setExt_ref(ext_ref_to_set);
                            ext_ref_ref.setDem_ex(dem_ex);
                            sessionc.save(ext_ref_ref);
                        }
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
        // Committing transaction, closing session and session factory
        txv.commit();
        sessionc.close();
        System.out.println("CWE data were put into the database");
    }

    ///**
    // * This method's purpose is to create a CWE object from given parameters and return it
    // *
    // * @return CWE object
    // */
    //public static CWEobject getInstance(String code_id, String name, String abstraction, String structure, String status, String description,
    //                                    String ext_description, String exploit_likelihood, List<CWErelationObj> relations, List<CWEapplPlatfObj> appl_platform_objs,
    //                                    List<String> bg_details, List<CWEnoteObj> notes, List<CWEintrModesObj> intr_modes,
    //                                    List<CWEconseqObj> consequences, List<CWEalterTermObj> alter_terms, List<CWEextRefRefObj> ext_ref_refs,
    //                                    List<CWEtaxMapObj> tax_maps, List<CWEpotMitObj> pot_mits, List<CWEweakOrdObj> weak_ords,
    //                                    List<CWEdemExObj> dem_examples, List<CWEobsExObj> obs_examples, List<CWEdetMethObj> det_meths,
    //                                    List<CAPECobject> capec, List<String> affected_resources, List<String> functional_areas) {

    //    return new CWEobject(code_id, name, abstraction, structure, status, description, ext_description, exploit_likelihood,
    //            relations, appl_platform_objs, bg_details, notes, intr_modes, consequences, alter_terms, ext_ref_refs, tax_maps,
    //            pot_mits, weak_ords, dem_examples, obs_examples, det_meths, capec, affected_resources, functional_areas);
    //}

    @Override
    public String toString() {
        return "CWEobject{" +
                "code_id='" + code_id + '\'' +
                ", name='" + name + '\'' +
                ", abstraction='" + abstraction + '\'' +
                ", structure='" + structure + '\'' +
                ", status='" + status + '\'' +
                ", description='" + description + '\'' +
                ", ext_description='" + ext_description + '\'' +
                ", exploit_likelihood='" + exploit_likelihood + '\'' +
                ", relations=" + relations +
                ", appl_platform_objs=" + appl_platform_objs +
                ", bg_details=" + bg_details +
                ", notes=" + notes +
                ", intr_modes=" + intr_modes +
                ", consequences=" + consequences +
                ", alter_terms=" + alter_terms +
                ", ext_ref_refs=" + ext_ref_refs +
                ", tax_maps=" + tax_maps +
                ", pot_mits=" + pot_mits +
                ", weak_ords=" + weak_ords +
                ", dem_examples=" + dem_examples +
                ", obs_examples=" + obs_examples +
                ", det_meths=" + det_meths +
                ", related_attack_patterns=" + capec +
                ", affected_resources=" + affected_resources +
                ", functional_areas=" + functional_areas +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEobject)) return false;
        CWEobject cwEobject = (CWEobject) o;
        return Objects.equals(code_id, cwEobject.code_id) && Objects.equals(name, cwEobject.name) && Objects.equals(abstraction, cwEobject.abstraction) && Objects.equals(structure, cwEobject.structure) && Objects.equals(status, cwEobject.status) && Objects.equals(description, cwEobject.description) && Objects.equals(ext_description, cwEobject.ext_description) && Objects.equals(exploit_likelihood, cwEobject.exploit_likelihood) && Objects.equals(relations, cwEobject.relations) && Objects.equals(appl_platform_objs, cwEobject.appl_platform_objs) && Objects.equals(bg_details, cwEobject.bg_details) && Objects.equals(capec, cwEobject.capec) && Objects.equals(notes, cwEobject.notes) && Objects.equals(intr_modes, cwEobject.intr_modes) && Objects.equals(consequences, cwEobject.consequences) && Objects.equals(alter_terms, cwEobject.alter_terms) && Objects.equals(ext_ref_refs, cwEobject.ext_ref_refs) && Objects.equals(tax_maps, cwEobject.tax_maps) && Objects.equals(pot_mits, cwEobject.pot_mits) && Objects.equals(weak_ords, cwEobject.weak_ords) && Objects.equals(dem_examples, cwEobject.dem_examples) && Objects.equals(obs_examples, cwEobject.obs_examples) && Objects.equals(det_meths, cwEobject.det_meths) && Objects.equals(affected_resources, cwEobject.affected_resources) && Objects.equals(functional_areas, cwEobject.functional_areas) && Objects.equals(cve, cwEobject.cve) && Objects.equals(relations_related, cwEobject.relations_related);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code_id, name, abstraction, structure, status, description, ext_description, exploit_likelihood, relations, appl_platform_objs, bg_details, capec, notes, intr_modes, consequences, alter_terms, ext_ref_refs, tax_maps, pot_mits, weak_ords, dem_examples, obs_examples, det_meths, affected_resources, functional_areas, cve, relations_related);
    }
}
