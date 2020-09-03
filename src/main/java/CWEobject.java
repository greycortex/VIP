/**
 * This class represents a CWE object (CWE name (ID) and description)
 *
 * --- Description of the class ---
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEobject {

    protected String id_name;
    protected String description;

    /**
     * Copies constructor
     *
     * @param id_name     CWE id of a specific CWE
     * @param description description of a specific CWE
     */
    public CWEobject(String id_name, String description) {

        this.id_name = id_name;
        this.description = description;

    }

}
