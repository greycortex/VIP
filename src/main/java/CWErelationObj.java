/**
 * This class represents a CWE relation object (nature attribute, CWE code (ID) of related CWE, view_id attribute, ordinal attribute)
 * <p>
 * //* It can create a CWE relation object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWErelationObj {

    protected String nature;
    protected String related_cwe_id;
    protected String view_id;
    protected String ordinal;

    /**
     * Copies constructor
     *
     * @param nature         nature attribute
     * @param related_cwe_id CWE code (ID) of related CWE
     * @param view_id        view_id attribute
     * @param ordinal        ordinal attribute
     */
    public CWErelationObj(String nature, String related_cwe_id, String view_id, String ordinal) {

        this.nature = nature;
        this.related_cwe_id = related_cwe_id;
        this.view_id = view_id;
        this.ordinal = ordinal;

    }

    /**
     * This method's purpose is to create a CWE relation object from given parameters and return it
     *
     * @return CWE relation object
     */
    public static CWErelationObj getInstance(String nature, String related_cwe_id, String view_id, String ordinal) {

        return new CWErelationObj(nature, related_cwe_id, view_id, ordinal);
    }

    @Override
    public String toString() {
        return "CWErelationObj{" +
                "nature='" + nature + '\'' +
                ", related_cwe_id='" + related_cwe_id + '\'' +
                ", view_id='" + view_id + '\'' +
                ", ordinal='" + ordinal + '\'' +
                '}';
    }
}
