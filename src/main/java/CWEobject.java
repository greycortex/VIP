import org.xml.sax.SAXException;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * This class represents a CWE object (CWE name (ID) and description)
 *
 * It can create a CWE object from given CWE id, it uses DOM XML parser to find description according to the specific
 * CWE id and create a CWE object containing both of them (CWE id, description)
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEobject {

    protected String id_name;
    protected String description;

    /**
     * Copies constructor
     *
     * @param id_name     CWE ID of a specific CWE
     * @param description description of a specific CWE
     */
    public CWEobject(String id_name, String description) {

        this.id_name = id_name;
        this.description = description;
    }

    /**
     * This method's purpose is to create a CWE object from given ID, add a description according to the input ID and return it
     *
     * It uses DOM XML parser
     * It takes input ID attribute, goes through file that contains latest list of CWE weaknesses,
     * finds a "Name" attribute (short description) relating to the input ID and
     * then returns a CWE object wih both of these attributes (id, description)
     *
     * If it can't find CWE weakness description by ID, it returns a CWE object with description value
     * "Description not found"
     *
     * @return CWE object (id, description found by id)
     */
    public static CWEobject createCWEobj(String id_name) {
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();

        try {
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document document = builder.parse(new FileInputStream("exclude/cwec_v4.2.xml")); // https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
            Element doc_element = document.getDocumentElement();
            NodeList nodes = doc_element.getChildNodes();

            for (int i = 0; i < nodes.getLength(); i++) {
                if (nodes.item(i).getNodeName().equals("Weaknesses")) {
                    NodeList nodes_weakness = nodes.item(i).getChildNodes();
                    for (int z = 0; z < nodes_weakness.getLength(); z++) {
                        if (nodes_weakness.item(z).getNodeName().equals("Weakness")) {
                            NamedNodeMap attr = nodes_weakness.item(z).getAttributes();
                            String id_from_file = attr.getNamedItem("ID").getNodeValue();
                            if (id_from_file.equals(id_name)) {
                                return new CWEobject(id_name, attr.getNamedItem("Name").getNodeValue());
                            }
                        }
                    }
                }
            }
        } catch (SAXException | IOException | ParserConfigurationException ex) {
            ex.printStackTrace();
        }
        return new CWEobject(id_name, "Description not found");
    }

    @Override
    public String toString() {
        return "CWEobject{" +
                "id_name='" + id_name + '\'' +
                ", description='" + description + '\'' +
                '}';
    }
}
