package mitre.cwe;

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
import java.util.List;

/**
 * This class represents a CWE category object (CWE category id, category name attribute, category status attribute,
 * category summary attribute, relationship objects (CWE ID, view ID), external reference reference objects)
 * <p>
 * //* It can create a CWE category object from given parameters and return it
 * <p>
 * It also can go through an XML file with CWE weaknesses or CAPEC objects, find category objects, parse them into
 * CWE category objects and return them
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEcategoryObj {

    protected String category_id;
    protected String category_name;
    protected String category_status;
    protected String category_summary;
    protected List<CWEnoteObj> category_notes;
    protected List<CWErelationshipObj> category_relationships;
    protected List<CWEextRefRefObj> category_ext_ref_refs;
    protected List<CWEtaxMapObj> category_tax_maps;

    /**
     * Copies constructor
     *
     * @param category_id            CWE category id
     * @param category_name          category name attribute
     * @param category_status        category status attribute
     * @param category_summary       category summary attribute
     * @param category_notes         note objects
     * @param category_relationships relationship objects (CWE ID, view ID)
     * @param category_ext_ref_refs  external reference reference objects
     * @param category_tax_maps      taxonomy mapping objects
     */
    public CWEcategoryObj(String category_id, String category_name, String category_status, String category_summary,
                          List<CWEnoteObj> category_notes, List<CWErelationshipObj> category_relationships,
                          List<CWEextRefRefObj> category_ext_ref_refs, List<CWEtaxMapObj> category_tax_maps) {

        this.category_id = category_id;
        this.category_name = category_name;
        this.category_status = category_status;
        this.category_summary = category_summary;
        this.category_notes = category_notes;
        this.category_relationships = category_relationships;
        this.category_ext_ref_refs = category_ext_ref_refs;
        this.category_tax_maps = category_tax_maps;

    }

    /**
     * This method's purpose is to go through an XML file with CWE weaknesses or CAPEC objects, find category objects,
     * parse them into CWE category objects and return them, deprecated ones not included
     * <p>
     * It uses DOM XML parser
     * <p>
     * If it can't find any informations, it returns these attributes as null values
     *
     * @param file path to an XML file which will be parsed from
     * @return CWE category objects
     */
    public static List<CWEcategoryObj> CWEcategoryToArrayList(String file) { // https://cwe.mitre.org/data/xml/cwec_latest.xml.zip or https://capec.mitre.org/data/xml/capec_latest.xml
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();

        List<CWEcategoryObj> category_objs = new ArrayList<>(); // creating empty List for it to be filled with CWE category objects

        try {
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document document = builder.parse(new FileInputStream(file));
            Element doc_element = document.getDocumentElement();
            NodeList nodes = doc_element.getChildNodes();

            for (int i = 0; i < nodes.getLength(); i++) {
                if (nodes.item(i).getNodeName().equals("Categories")) {
                    NodeList categories_nodes = nodes.item(i).getChildNodes();

                    for (int y = 0; y < categories_nodes.getLength(); y++) {
                        if (categories_nodes.item(y).getNodeName().equals("Category")) {

                            NamedNodeMap category_attr = categories_nodes.item(y).getAttributes();
                            String cat_category_status = category_attr.getNamedItem("Status").getNodeValue(); // getting status attribute

                            if (cat_category_status.equals("Deprecated"))
                                ; // if the category is deprecated, it won't be returned
                            else {

                                String cat_category_id = category_attr.getNamedItem("ID").getNodeValue(); // getting ID attribute
                                String cat_category_name = category_attr.getNamedItem("Name").getNodeValue(); // getting name attribute

                                String cat_category_summary = null;
                                List<CWEnoteObj> cat_category_notes = new ArrayList<>();
                                List<CWErelationshipObj> cat_category_relationships = new ArrayList<>();
                                List<CWEextRefRefObj> cat_category_ext_ref_refs = new ArrayList<>();
                                List<CWEtaxMapObj> cat_category_tax_maps = new ArrayList<>();

                                NodeList category_specific_nodes = categories_nodes.item(y).getChildNodes();

                                for (int z = 0; z < category_specific_nodes.getLength(); z++) {
                                    if (category_specific_nodes.item(z).getNodeName().equals("Summary")) {
                                        cat_category_summary = category_specific_nodes.item(z).getTextContent(); // getting summary attribute

                                    } else if (category_specific_nodes.item(z).getNodeName().equals("Notes")) {
                                        NodeList category_note_nodes = category_specific_nodes.item(z).getChildNodes();

                                        for (int g = 0; g < category_note_nodes.getLength(); g++) {
                                            if (category_note_nodes.item(g).getNodeName().equals("Note")) {
                                                NamedNodeMap cat_note_attr = category_note_nodes.item(g).getAttributes();
                                                String cat_note_type = cat_note_attr.getNamedItem("Type").getNodeValue(); // getting type attribute - note object
                                                String cat_note_content = category_note_nodes.item(g).getTextContent(); // getting note content - note object

                                                cat_category_notes.add(new CWEnoteObj(cat_note_type, cat_note_content)); // creating new note object
                                            }
                                        }

                                    } else if (category_specific_nodes.item(z).getNodeName().equals("Relationships")) {
                                        NodeList category_relation_nodes = category_specific_nodes.item(z).getChildNodes();

                                        for (int g = 0; g < category_relation_nodes.getLength(); g++) {
                                            if (category_relation_nodes.item(g).getNodeName().equals("Has_Member")) {
                                                String cat_capec_id = null;
                                                String cat_cwe_id = null;
                                                String cat_view_id = null;
                                                NamedNodeMap cat_relation_attr = category_relation_nodes.item(g).getAttributes();

                                                if (file == "exclude/capec_latest.xml"){
                                                    cat_capec_id = cat_relation_attr.getNamedItem("CAPEC_ID").getNodeValue(); // getting CAPEC ID attribute - relationship (member) object

                                                } else if (file == "exclude/cwec_v4.2.xml"){
                                                    cat_cwe_id = cat_relation_attr.getNamedItem("CWE_ID").getNodeValue(); // getting CWE ID attribute - relationship (member) object
                                                    cat_view_id = cat_relation_attr.getNamedItem("View_ID").getNodeValue(); // getting view ID attribute - relationship (member) object
                                                }

                                                cat_category_relationships.add(new CWErelationshipObj(cat_cwe_id, cat_view_id, cat_capec_id)); // creating new relationship (member) object
                                            }
                                        }

                                    } else if (category_specific_nodes.item(z).getNodeName().equals("References")) {
                                        NodeList category_reference_nodes = category_specific_nodes.item(z).getChildNodes();

                                        for (int g = 0; g < category_reference_nodes.getLength(); g++) {
                                            if (category_reference_nodes.item(g).getNodeName().equals("Reference")) {
                                                NamedNodeMap cat_reference_attr = category_reference_nodes.item(g).getAttributes();
                                                String cat_ext_ref_id = cat_reference_attr.getNamedItem("External_Reference_ID").getNodeValue(); // getting ext. ref. ID attribute - external reference reference object

                                                String cat_ext_ref_section = null;
                                                if (cat_reference_attr.getNamedItem("Section") != null) {
                                                    cat_ext_ref_section = cat_reference_attr.getNamedItem("Section").getNodeValue(); // getting section attribute - external reference reference object
                                                }

                                                cat_category_ext_ref_refs.add(new CWEextRefRefObj(cat_ext_ref_id, cat_ext_ref_section)); // creating new external reference reference object
                                            }
                                        }

                                    } else if (category_specific_nodes.item(z).getNodeName().equals("Taxonomy_Mappings")) {
                                        NodeList cat_tax_map_nodes = category_specific_nodes.item(z).getChildNodes();

                                        for (int c = 0; c < cat_tax_map_nodes.getLength(); c++) {
                                            if (cat_tax_map_nodes.item(c).getNodeName().equals("Taxonomy_Mapping")) {
                                                NamedNodeMap tax_map_attr = cat_tax_map_nodes.item(c).getAttributes();
                                                NodeList tax_map_specific_nodes = cat_tax_map_nodes.item(c).getChildNodes();

                                                String cat_tax_name = tax_map_attr.getNamedItem("Taxonomy_Name").getNodeValue(); // getting name attribute - taxonomy mapping object
                                                String cat_tax_entry_name = null;
                                                String cat_tax_entry_id = null;
                                                String cat_tax_map_fit = null;

                                                for (int v = 0; v < tax_map_specific_nodes.getLength(); v++) {
                                                    if (tax_map_specific_nodes.item(v).getNodeName().equals("Entry_Name")) {
                                                        cat_tax_entry_name = tax_map_specific_nodes.item(v).getTextContent(); // getting entry name attribute - taxonomy mapping object

                                                    } else if (tax_map_specific_nodes.item(v).getNodeName().equals("Entry_ID")) {
                                                        cat_tax_entry_id = tax_map_specific_nodes.item(v).getTextContent(); // getting entry ID attribute - taxonomy mapping object

                                                    } else if (tax_map_specific_nodes.item(v).getNodeName().equals("Mapping_Fit")) {
                                                        cat_tax_map_fit = tax_map_specific_nodes.item(v).getTextContent(); // getting mapping fit attribute - taxonomy mapping object

                                                    }
                                                }

                                                cat_category_tax_maps.add(new CWEtaxMapObj(cat_tax_name, cat_tax_entry_name, cat_tax_entry_id, cat_tax_map_fit)); // creating new taxonomy mapping object
                                            }
                                        }
                                    }
                                }

                                category_objs.add(new CWEcategoryObj(cat_category_id, cat_category_name, cat_category_status, cat_category_summary,
                                        cat_category_notes, cat_category_relationships, cat_category_ext_ref_refs,
                                        cat_category_tax_maps)); // creating new category object
                            }
                        }
                    }
                }
            }
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            ex.printStackTrace();
        }

        return category_objs; // returns List filled with CWE category objects
    }

    ///**
    // * This method's purpose is to create a CWE category object from given parameters and return it
    // *
    // * @return CWE category object
    // */
    //public static CWEcategoryObj getInstance(String category_id, String category_name, String category_status, String category_summary,
    //                                         List<CWEnoteObj> category_notes, List<CWErelationshipObj> category_relationships,
    //                                         List<CWEextRefRefObj> category_ext_ref_refs, List<CWEtaxMapObj> category_tax_maps) {

    //    return new CWEcategoryObj(category_id, category_name, category_status, category_summary, category_notes, category_relationships,
    //            category_ext_ref_refs, category_tax_maps);
    //}

    @Override
    public String toString() {
        return "CWEcategoryObj{" +
                "category_id='" + category_id + '\'' +
                ", category_name='" + category_name + '\'' +
                ", category_status='" + category_status + '\'' +
                ", category_summary='" + category_summary + '\'' +
                ", category_notes=" + category_notes +
                ", category_relationships=" + category_relationships +
                ", category_ext_ref_refs=" + category_ext_ref_refs +
                ", category_tax_maps=" + category_tax_maps +
                '}';
    }
}
