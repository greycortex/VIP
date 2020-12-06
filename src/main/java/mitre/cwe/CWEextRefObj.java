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
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * This class represents a CWE external reference object (reference ID attribute, author attributes, )
 * <p>
 * //* It can create a CWE external reference object from given parameters and return it
 * <p>
 * It also can go through file with CWE weaknesses or CAPEC objects, find external reference objects, parse them into
 * CWE external reference objects and return them
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEextRefObj {

    protected String reference_id;
    protected String title;
    protected String url;
    protected String publication;
    protected String publisher;
    protected String edition;
    protected List<String> authors;
    protected Date publication_date;
    protected Date url_date;

    /**
     * Copies constructor
     *
     * @param reference_id     CWE external reference ID
     * @param title            title attribute
     * @param url              url attribute
     * @param publication      publication attribute
     * @param publisher        publisher attribute
     * @param edition          edition attribute
     * @param authors          author attributes
     * @param publication_date publication date of a specific CWE external reference
     * @param url_date         URL date attribute
     */
    public CWEextRefObj(String reference_id, String title, String url, String publication, String publisher, String edition,
                        List<String> authors, Date publication_date, Date url_date) {

        this.reference_id = reference_id;
        this.title = title;
        this.url = url;
        this.publication = publication;
        this.publisher = publisher;
        this.edition = edition;
        this.authors = authors;
        this.publication_date = publication_date;
        this.url_date = url_date;

    }

    /**
     * This method's purpose is to go through file with CWE weaknesses or CAPEC objects, find external reference objects,
     * parse them into CWE external reference objects and return them
     * <p>
     * It uses DOM XML parser
     * <p>
     * If it can't find any informations, it returns these attributes as null values
     *
     * @param file path to an XML file which will be parsed from
     * @return CWE external reference objects
     */
    public static List<CWEextRefObj> CWEextRefToArrayList(String file) { // https://cwe.mitre.org/data/xml/cwec_latest.xml.zip or https://capec.mitre.org/data/xml/capec_latest.xml
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();

        List<CWEextRefObj> ext_ref_objs = new ArrayList<>(); // creating empty List for it to be filled with CWE external reference objects

        try {
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            Document document = builder.parse(new FileInputStream(file));
            Element doc_element = document.getDocumentElement();
            NodeList nodes = doc_element.getChildNodes();

            for (int i = 0; i < nodes.getLength(); i++) {
                if (nodes.item(i).getNodeName().equals("External_References")) {
                    NodeList ext_refs_nodes = nodes.item(i).getChildNodes();

                    for (int y = 0; y < ext_refs_nodes.getLength(); y++) {
                        if (ext_refs_nodes.item(y).getNodeName().equals("External_Reference")) {
                            NodeList ext_refs_specific_nodes = ext_refs_nodes.item(y).getChildNodes();

                            NamedNodeMap ext_ref_attr = ext_refs_nodes.item(y).getAttributes();
                            String ext_ref_id = ext_ref_attr.getNamedItem("Reference_ID").getNodeValue(); // getting reference id attribute

                            String ext_ref_title = null;
                            String ext_ref_url = null;
                            String ext_ref_publ_day = null;
                            String ext_ref_publ_month = null;
                            String ext_ref_publ_year = null;
                            List<String> ext_ref_authors = new ArrayList<>();
                            String ext_ref_publication = null;
                            String ext_ref_publisher = null;
                            String ext_ref_edition = null;
                            Date ext_ref_url_date = null;
                            Date ext_ref_publ_date = null;

                            for (int z = 0; z < ext_refs_specific_nodes.getLength(); z++) {
                                if (ext_refs_specific_nodes.item(z).getNodeName().equals("Title")) {
                                    ext_ref_title = ext_refs_specific_nodes.item(z).getTextContent(); // getting title attribute

                                } else if (ext_refs_specific_nodes.item(z).getNodeName().equals("URL")) {
                                    ext_ref_url = ext_refs_specific_nodes.item(z).getTextContent(); // getting URL attribute

                                } else if (ext_refs_specific_nodes.item(z).getNodeName().equals("Publication_Day")) {
                                    ext_ref_publ_day = ext_refs_specific_nodes.item(z).getTextContent(); // getting publication day attribute

                                } else if (ext_refs_specific_nodes.item(z).getNodeName().equals("Publication_Month")) {
                                    ext_ref_publ_month = ext_refs_specific_nodes.item(z).getTextContent(); // getting publication month attribute

                                } else if (ext_refs_specific_nodes.item(z).getNodeName().equals("Publication_Year")) {
                                    ext_ref_publ_year = ext_refs_specific_nodes.item(z).getTextContent(); // getting publication year attribute

                                } else if (ext_refs_specific_nodes.item(z).getNodeName().equals("Author")) {
                                    ext_ref_authors.add(ext_refs_specific_nodes.item(z).getTextContent()); // getting author attribute

                                } else if (ext_refs_specific_nodes.item(z).getNodeName().equals("Publication")) {
                                    ext_ref_publication = ext_refs_specific_nodes.item(z).getTextContent(); // getting publication attribute

                                } else if (ext_refs_specific_nodes.item(z).getNodeName().equals("Publisher")) {
                                    ext_ref_publisher = ext_refs_specific_nodes.item(z).getTextContent(); // getting publisher attribute

                                } else if (ext_refs_specific_nodes.item(z).getNodeName().equals("Edition")) {
                                    ext_ref_edition = ext_refs_specific_nodes.item(z).getTextContent(); // getting edition attribute

                                } else if (ext_refs_specific_nodes.item(z).getNodeName().equals("URL_Date")) {

                                    DateFormat dateformat_month_year_day = new SimpleDateFormat("yyyy-MM-dd");
                                    String ext_ref_url_date_string = ext_refs_specific_nodes.item(z).getTextContent(); // getting URL date attribute
                                    ext_ref_url_date = dateformat_month_year_day.parse(ext_ref_url_date_string); // getting URL date attribute
                                }
                            }

                            if (ext_ref_publ_day != null && ext_ref_publ_month != null && ext_ref_publ_year != null) {
                                ext_ref_publ_day = ext_ref_publ_day.replaceAll("-", "");
                                ext_ref_publ_month = ext_ref_publ_month.replaceAll("-", "");

                                DateFormat dateformat_month_year_day = new SimpleDateFormat("yyyy-MM-dd");
                                String ext_ref_publ_date_string = ext_ref_publ_year + "-" + ext_ref_publ_month + "-" + ext_ref_publ_day;
                                ext_ref_publ_date = dateformat_month_year_day.parse(ext_ref_publ_date_string); // getting publication date attribute

                            } else if (ext_ref_publ_day == null && ext_ref_publ_month != null && ext_ref_publ_year != null) {
                                ext_ref_publ_month = ext_ref_publ_month.replaceAll("-", "");

                                DateFormat dateformat_month_year = new SimpleDateFormat("yyyy-MM");
                                String ext_ref_publ_date_string = ext_ref_publ_year + "-" + ext_ref_publ_month;
                                ext_ref_publ_date = dateformat_month_year.parse(ext_ref_publ_date_string); // getting publication date attribute

                            } else if (ext_ref_publ_day == null && ext_ref_publ_month == null && ext_ref_publ_year != null) {
                                DateFormat dateformat_year = new SimpleDateFormat("yyyy");
                                ext_ref_publ_date = dateformat_year.parse(ext_ref_publ_year); // getting publication date attribute

                            }

                            ext_ref_objs.add(new CWEextRefObj(ext_ref_id, ext_ref_title, ext_ref_url, ext_ref_publication,
                                    ext_ref_publisher, ext_ref_edition, ext_ref_authors, ext_ref_publ_date,
                                    ext_ref_url_date)); // creating CWE external reference object and adding it into later returned List
                        }
                    }
                }
            }
        } catch (SAXException | IOException | ParserConfigurationException | ParseException ex) {
            ex.printStackTrace();
        }

        return ext_ref_objs; // returning List full of CWE external reference objects
    }

    ///**
    // * This method's purpose is to create a CWE external reference object from given parameters and return it
    // *
    // * @return CWE external reference object
    // */
    //public static CWEextRefObj getInstance(String reference_id, String title, String url, String publication, String publisher, String edition,
    //                                       List<String> authors, Date publication_date, Date url_date) {

    //    return new CWEextRefObj(reference_id, title, url, publication, publisher, edition, authors, publication_date, url_date);
    //}

    @Override
    public String toString() {
        return "CWEextRefObj{" +
                "reference_id='" + reference_id + '\'' +
                ", title='" + title + '\'' +
                ", url='" + url + '\'' +
                ", publication='" + publication + '\'' +
                ", publisher='" + publisher + '\'' +
                ", edition='" + edition + '\'' +
                ", authors=" + authors +
                ", publication_date=" + publication_date +
                ", url_date=" + url_date +
                '}';
    }
}
