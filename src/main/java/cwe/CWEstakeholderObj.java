package cwe;

/**
 * This class represents a CWE stakeholder object (type attribute, description attribute)
 * <p>
 * //* It can create a CWE stakeholder object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEstakeholderObj {

    protected String type;
    protected String description;

    /**
     * Copies constructor
     *
     * @param type        type attribute
     * @param description description attribute
     */
    public CWEstakeholderObj(String type, String description) {

        this.type = type;
        this.description = description;

    }

    /**
     * This method's purpose is to create a CWE stakeholder object from given parameters and return it
     *
     * @return CWE stakeholder object
     */
    public static CWEstakeholderObj getInstance(String type, String description) {

        return new CWEstakeholderObj(type, description);
    }

    @Override
    public String toString() {
        return "CWEstakeholderObj{" +
                "type='" + type + '\'' +
                ", description='" + description + '\'' +
                '}';
    }
}
