package mitre.cwe;

import java.util.Objects;

/**
 * This class represents a CWE relationship (member) object (CWE ID attribute or CAPEC ID attribute, view ID attribute)
 * <p>
 * //* It can create a CWE relationship (member) object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWErelationshipObj {

    protected String cwe_id;
    protected String view_id;
    protected String capec_id;

    /**
     * Copies constructor
     *
     * @param cwe_id    CWE ID attribute
     * @param view_id   view ID attribute
     * @param capec_id  CAPEC ID attribute
     */
    public CWErelationshipObj(String cwe_id, String view_id, String capec_id) {

        this.cwe_id = cwe_id;
        this.view_id = view_id;
        this.capec_id = capec_id;

    }

    ///**
    // * This method's purpose is to create a CWE relationship (member) object from given parameters and return it
    // *
    // * @return CWE relationship (member) object
    // */
    //public static CWErelationshipObj getInstance(String cwe_id, String view_id, String capec_id) {

    //    return new CWErelationshipObj(cwe_id, view_id, capec_id);
    //}

    @Override
    public String toString() {
        return "CWErelationshipObj{" +
                "cwe_id='" + cwe_id + '\'' +
                ", view_id='" + view_id + '\'' +
                ", capec_id='" + capec_id + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWErelationshipObj)) return false;
        CWErelationshipObj that = (CWErelationshipObj) o;
        return Objects.equals(cwe_id, that.cwe_id) && Objects.equals(view_id, that.view_id) && Objects.equals(capec_id, that.capec_id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(cwe_id, view_id, capec_id);
    }
}
