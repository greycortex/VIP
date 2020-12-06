package mitre.cwe;

/**
 * This class represents a CWE observed example object (reference attribute, description attribute, link attribute)
 * <p>
 * //* It can create a CWE observed example object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEobsExObj {

    protected String reference;
    protected String description;
    protected String link;

    /**
     * Copies constructor
     *
     * @param reference   reference attribute
     * @param description description attribute
     * @param link        link attribute
     */
    public CWEobsExObj(String reference, String description, String link) {

        this.reference = reference;
        this.description = description;
        this.link = link;

    }

    ///**
    // * This method's purpose is to create a CWE observed example object from given parameters and return it
    // *
    // * @return CWE observed example object
    // */
    //public static CWEobsExObj getInstance(String reference, String description, String link) {

    //    return new CWEobsExObj(reference, description, link);
    //}

    @Override
    public String toString() {
        return "CWEobsExObj{" +
                "reference='" + reference + '\'' +
                ", description='" + description + '\'' +
                ", link='" + link + '\'' +
                '}';
    }
}
