/**
 * This class represents a CWE relationship (member) object (CWE ID attribute, view ID attribute)
 * <p>
 * //* It can create a CWE relationship (member) object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWErelationshipObj {

    protected String cwe_id;
    protected String view_id;

    /**
     * Copies constructor
     *
     * @param cwe_id  CWE ID attribute
     * @param view_id view ID attribute
     */
    public CWErelationshipObj(String cwe_id, String view_id) {

        this.cwe_id = cwe_id;
        this.view_id = view_id;

    }

    /**
     * This method's purpose is to create a CWE relationship (member) object from given parameters and return it
     *
     * @return CWE relationship (member) object
     */
    public static CWErelationshipObj getInstance(String cwe_id, String view_id) {

        return new CWErelationshipObj(cwe_id, view_id);
    }

    @Override
    public String toString() {
        return "CWErelationshipObj{" +
                "cwe_id='" + cwe_id + '\'' +
                ", view_id='" + view_id + '\'' +
                '}';
    }
}
