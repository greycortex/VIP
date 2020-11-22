package mitre.cwe;

/**
 * This class represents a CWE external reference reference object (ID attribute, section attribute)
 * <p>
 * //* It can create a CWE external reference reference object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEextRefRefObj {

    protected String ext_ref_id;
    protected String section;

    /**
     * Copies constructor
     *
     * @param ext_ref_id external reference id
     * @param section    section content
     */
    public CWEextRefRefObj(String ext_ref_id, String section) {

        this.ext_ref_id = ext_ref_id;
        this.section = section;

    }

    /**
     * This method's purpose is to create a CWE external reference reference object from given parameters and return it
     *
     * @return CWE external reference reference object
     */
    public static CWEextRefRefObj getInstance(String ext_ref_id, String section) {

        return new CWEextRefRefObj(ext_ref_id, section);
    }

    @Override
    public String toString() {
        return "CWEextRefRefObj{" +
                "ext_ref_id='" + ext_ref_id + '\'' +
                ", section='" + section + '\'' +
                '}';
    }
}
