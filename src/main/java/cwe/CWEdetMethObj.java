package cwe;

/**
 * This class represents a CWE detection method object (method id attribute, method attribute, description attribute,
 * effectiveness attribute, effectiveness notes attribute)
 * <p>
 * //* It can create a CWE detection method object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEdetMethObj {

    protected String method_id;
    protected String method;
    protected String description;
    protected String effectiveness;
    protected String effectiveness_notes;


    /**
     * Copies constructor
     *
     * @param method_id           method id attribute
     * @param method              method attribute
     * @param description         description attribute
     * @param effectiveness       effectiveness attribute
     * @param effectiveness_notes effectiveness notes attribute
     */
    public CWEdetMethObj(String method_id, String method, String description, String effectiveness, String effectiveness_notes) {

        this.method_id = method_id;
        this.method = method;
        this.description = description;
        this.effectiveness = effectiveness;
        this.effectiveness_notes = effectiveness_notes;

    }

    /**
     * This method's purpose is to create a CWE detection method object from given parameters and return it
     *
     * @return CWE detection method object
     */
    public static CWEdetMethObj getInstance(String method_id, String method, String description, String effectiveness, String effectiveness_notes) {

        return new CWEdetMethObj(method_id, method, description, effectiveness, effectiveness_notes);
    }

    @Override
    public String toString() {
        return "CWEdetMethObj{" +
                "method_id='" + method_id + '\'' +
                ", method='" + method + '\'' +
                ", description='" + description + '\'' +
                ", effectiveness='" + effectiveness + '\'' +
                ", effectiveness_notes='" + effectiveness_notes + '\'' +
                '}';
    }
}
