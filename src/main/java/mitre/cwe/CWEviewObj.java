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
 * This class represents a CWE view object (CWE view ID, name attribute, type attribute, status attribute,
 * objective attribute, filter attribute, relationship objects, note objects, external reference reference objects)
 * <p>
 * //* It can create a CWE view object from given parameters and return it
 * <p>
 * It also can go through an XML file with CWE weaknesses or CAPEC objects, find view objects, parse them into
 * CWE view objects and return them, deprecated ones not included
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEviewObj {

    protected String view_id;
    protected String view_name;
    protected String view_type;
    protected String view_status;
    protected String view_objective;
    protected String view_filter;
    protected List<CWErelationshipObj> view_members;
    protected List<CWEnoteObj> view_notes;
    protected List<CWEextRefRefObj> view_ext_refs;
    protected List<CWEstakeholderObj> view_stakeholders;

    /**
     * Copies constructor
     *
     * @param view_id           CWE view id
     * @param view_name         name attribute
     * @param view_type         type attribute
     * @param view_status       status attribute
     * @param view_objective    objective attribute
     * @param view_filter       filter attribute
     * @param view_members      relationship objects
     * @param view_notes        note objects
     * @param view_ext_refs     external reference reference objects
     * @param view_stakeholders stakeholder objects
     */
    public CWEviewObj(String view_id, String view_name, String view_type, String view_status, String view_objective,
                      String view_filter, List<CWErelationshipObj> view_members, List<CWEnoteObj> view_notes,
                      List<CWEextRefRefObj> view_ext_refs, List<CWEstakeholderObj> view_stakeholders) {

        this.view_id = view_id;
        this.view_name = view_name;
        this.view_type = view_type;
        this.view_status = view_status;
        this.view_objective = view_objective;
        this.view_filter = view_filter;
        this.view_members = view_members;
        this.view_notes = view_notes;
        this.view_ext_refs = view_ext_refs;
        this.view_stakeholders = view_stakeholders;

    }

    /**
     * This method's purpose is to go through an XML file with CWE weaknesses or CAPEC objects, find view objects, parse them into
     * CWE view objects and return them
     * <p>
     * It uses DOM XML parser
     * <p>
     * If it can't find any informations, it returns these attributes as null values
     *
     * @param file path to an XML file which will be parsed from
     * @return CWE view objects
     */
    public static List<CWEviewObj> CWEviewToArrayList(String file) { // https://cwe.mitre.org/data/xml/cwec_latest.xml.zip or https://capec.mitre.org/data/xml/capec_latest.xml
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();

        List<CWEviewObj> view_objs = new ArrayList<>(); // creating empty List for it to be filled with CWE view objects

        try {
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document document = builder.parse(new FileInputStream(file));
            Element doc_element = document.getDocumentElement();
            NodeList nodes = doc_element.getChildNodes();

            for (int i = 0; i < nodes.getLength(); i++) {
                if (nodes.item(i).getNodeName().equals("Views")) {
                    NodeList views_nodes = nodes.item(i).getChildNodes();

                    for (int y = 0; y < views_nodes.getLength(); y++) {
                        if (views_nodes.item(y).getNodeName().equals("View")) {
                            NodeList view_specific_nodes = views_nodes.item(y).getChildNodes();

                            NamedNodeMap view_attr = views_nodes.item(y).getAttributes();
                            String view_view_status = view_attr.getNamedItem("Status").getNodeValue(); // getting status attribute

                            if (view_view_status.equals("Deprecated"))
                                ; // if the view is deprecated, it won't be returned
                            else {

                                String view_view_id = view_attr.getNamedItem("ID").getNodeValue(); // getting ID attribute
                                String view_view_name = view_attr.getNamedItem("Name").getNodeValue(); // getting name attribute
                                String view_view_type = view_attr.getNamedItem("Type").getNodeValue(); // getting type attribute

                                String view_view_objective = null;
                                String view_view_filter = null;
                                List<CWErelationshipObj> view_view_members = new ArrayList<>();
                                List<CWEnoteObj> view_view_notes = new ArrayList<>();
                                List<CWEextRefRefObj> view_view_ext_refs = new ArrayList<>();
                                List<CWEstakeholderObj> view_view_stakeholders = new ArrayList<>();

                                for (int z = 0; z < view_specific_nodes.getLength(); z++) {
                                    if (view_specific_nodes.item(z).getNodeName().equals("Objective")) {
                                        view_view_objective = view_specific_nodes.item(z).getTextContent(); // getting objective attribute

                                    } else if (view_specific_nodes.item(z).getNodeName().equals("Notes")) {
                                        NodeList view_note_nodes = view_specific_nodes.item(z).getChildNodes();

                                        for (int g = 0; g < view_note_nodes.getLength(); g++) {
                                            if (view_note_nodes.item(g).getNodeName().equals("Note")) {
                                                NamedNodeMap view_note_attr = view_note_nodes.item(g).getAttributes();
                                                String view_note_type = view_note_attr.getNamedItem("Type").getNodeValue(); // getting type attribute - note object
                                                String view_note_content = view_note_nodes.item(g).getTextContent(); // getting note content - note object

                                                view_view_notes.add(new CWEnoteObj(view_note_type, view_note_content)); // creating new note object
                                            }
                                        }

                                    } else if (view_specific_nodes.item(z).getNodeName().equals("Members")) {
                                        NodeList view_relation_nodes = view_specific_nodes.item(z).getChildNodes();

                                        for (int g = 0; g < view_relation_nodes.getLength(); g++) {
                                            if (view_relation_nodes.item(g).getNodeName().equals("Has_Member")) {
                                                String view_view_view_id = null;
                                                String view_cwe_id = null;
                                                String view_capec_id = null;
                                                NamedNodeMap view_relation_attr = view_relation_nodes.item(g).getAttributes();

                                                if (file == "exclude/capec_latest.xml"){
                                                    view_capec_id = view_relation_attr.getNamedItem("CAPEC_ID").getNodeValue(); // getting CAPEC ID attribute - relationship (member) object

                                                } else if (file == "exclude/cwec_v4.2.xml"){
                                                    view_cwe_id = view_relation_attr.getNamedItem("CWE_ID").getNodeValue(); // getting CWE ID attribute - relationship (member) object
                                                    view_view_view_id = view_relation_attr.getNamedItem("View_ID").getNodeValue(); // getting view ID attribute - relationship (member) object
                                                }

                                                view_view_members.add(new CWErelationshipObj(view_cwe_id, view_view_view_id, view_capec_id)); // creating new relationship (member) object
                                            }
                                        }

                                    } else if (view_specific_nodes.item(z).getNodeName().equals("Audience")) {
                                        NodeList view_audience_nodes = view_specific_nodes.item(z).getChildNodes();

                                        for (int r = 0; r < view_audience_nodes.getLength(); r++) {
                                            if (view_audience_nodes.item(r).getNodeName().equals("Stakeholder")) {
                                                NodeList stakeholder_nodes = view_audience_nodes.item(r).getChildNodes();

                                                String stakeholder_type = null;
                                                String stakeholder_descr = null;

                                                for (int l = 0; l < stakeholder_nodes.getLength(); l++) {
                                                    if (stakeholder_nodes.item(l).getNodeName().equals("Type")) {
                                                        stakeholder_type = stakeholder_nodes.item(l).getTextContent(); // getting type attribute - stakeholder object

                                                    } else if (stakeholder_nodes.item(l).getNodeName().equals("Description")) {
                                                        stakeholder_descr = stakeholder_nodes.item(l).getTextContent(); // getting description attribute - stakeholder object

                                                    }
                                                }

                                                view_view_stakeholders.add(new CWEstakeholderObj(stakeholder_type, stakeholder_descr)); // creating new stakeholder object
                                            }
                                        }

                                    } else if (view_specific_nodes.item(z).getNodeName().equals("References")) {
                                        NodeList view_reference_nodes = view_specific_nodes.item(z).getChildNodes();

                                        for (int g = 0; g < view_reference_nodes.getLength(); g++) {
                                            if (view_reference_nodes.item(g).getNodeName().equals("Reference")) {
                                                NamedNodeMap view_reference_attr = view_reference_nodes.item(g).getAttributes();

                                                // getting external reference ID attribute - external reference reference object
                                                String view_ext_ref_id = view_reference_attr.getNamedItem("External_Reference_ID").getNodeValue();

                                                String view_ext_ref_section = null;
                                                if (view_reference_attr.getNamedItem("Section") != null) {
                                                    view_ext_ref_section = view_reference_attr.getNamedItem("Section").getNodeValue(); // getting section attribute - external reference reference object
                                                }

                                                view_view_ext_refs.add(new CWEextRefRefObj(view_ext_ref_id, view_ext_ref_section)); // creating new external reference reference object
                                            }
                                        }

                                    } else if (view_specific_nodes.item(z).getNodeName().equals("Filter")) {
                                        view_view_filter = view_specific_nodes.item(z).getTextContent(); // getting filter attribute

                                    }
                                }

                                view_objs.add(new CWEviewObj(view_view_id, view_view_name, view_view_type, view_view_status,
                                        view_view_objective, view_view_filter, view_view_members, view_view_notes, view_view_ext_refs,
                                        view_view_stakeholders)); // creating new view object
                            }
                        }
                    }
                }
            }
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            ex.printStackTrace();
        }

        return view_objs; // returns List filled with CWE view objects
    }

    ///**
    // * This method's purpose is to create a CWE view object from given parameters and return it
    // *
    // * @return CWE view object
    // */
    //public static CWEviewObj getInstance(String view_id, String view_name, String view_type, String view_status, String view_objective,
    //                                     String view_filter, List<CWErelationshipObj> view_members, List<CWEnoteObj> view_notes,
    //                                     List<CWEextRefRefObj> view_ext_refs, List<CWEstakeholderObj> view_stakeholders) {

    //    return new CWEviewObj(view_id, view_name, view_type, view_status, view_objective, view_filter, view_members, view_notes,
    //            view_ext_refs, view_stakeholders);
    //}

    @Override
    public String toString() {
        return "CWEviewObj{" +
                "view_id='" + view_id + '\'' +
                ", view_name='" + view_name + '\'' +
                ", view_type='" + view_type + '\'' +
                ", view_status='" + view_status + '\'' +
                ", view_objective='" + view_objective + '\'' +
                ", view_filter='" + view_filter + '\'' +
                ", view_members=" + view_members +
                ", view_notes=" + view_notes +
                ", view_ext_refs=" + view_ext_refs +
                ", view_stakeholders=" + view_stakeholders +
                '}';
    }
}
