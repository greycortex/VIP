package extended_mitre.cwe;

import java.util.Objects;

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

    ///**
    // * This method's purpose is to create a CWE stakeholder object from given parameters and return it
    // *
    // * @return CWE stakeholder object
    // */
    //public static CWEstakeholderObj getInstance(String type, String description) {

    //    return new CWEstakeholderObj(type, description);
    //}

    @Override
    public String toString() {
        return "CWEstakeholderObj{" +
                "type='" + type + '\'' +
                ", description='" + description + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEstakeholderObj)) return false;
        CWEstakeholderObj that = (CWEstakeholderObj) o;
        return Objects.equals(type, that.type) && Objects.equals(description, that.description);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, description);
    }
}
