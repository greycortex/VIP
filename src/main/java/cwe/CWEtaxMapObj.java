package cwe;

/**
 * This class represents a CWE taxonomy mapping object (name, entry name attribute, entry ID, mapping fit attribute)
 * <p>
 * //* It can create a CWE taxonomy mapping object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEtaxMapObj {

    protected String name;
    protected String entry_name;
    protected String entry_id;
    protected String mapping_fit;

    /**
     * Copies constructor
     *
     * @param name        name
     * @param entry_name  entry name attribute
     * @param entry_id    entry ID attribute
     * @param mapping_fit mapping fit attribute
     */
    public CWEtaxMapObj(String name, String entry_name, String entry_id, String mapping_fit) {

        this.name = name;
        this.entry_name = entry_name;
        this.entry_id = entry_id;
        this.mapping_fit = mapping_fit;

    }

    /**
     * This method's purpose is to create a CWE taxonomy mapping object from given parameters and return it
     *
     * @return CWE taxonomy mapping object
     */
    public static CWEtaxMapObj getInstance(String name, String entry_name, String entry_id, String mapping_fit) {

        return new CWEtaxMapObj(name, entry_name, entry_id, mapping_fit);
    }

    @Override
    public String toString() {
        return "CWEtaxMapObj{" +
                "name='" + name + '\'' +
                ", entry_name='" + entry_name + '\'' +
                ", entry_id='" + entry_id + '\'' +
                ", mapping_fit='" + mapping_fit + '\'' +
                '}';
    }
}
