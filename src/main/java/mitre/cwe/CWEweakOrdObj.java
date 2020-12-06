package mitre.cwe;

/**
 * This class represents a CWE weakness ordinality object (ordinality attribute, description attribute)
 * <p>
 * //* It can create a CWE weakness ordinality object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEweakOrdObj {

    protected String ordinality;
    protected String description;

    /**
     * Copies constructor
     *
     * @param ordinality  ordinality attribute
     * @param description description attribute
     */
    public CWEweakOrdObj(String ordinality, String description) {

        this.ordinality = ordinality;
        this.description = description;

    }

    ///**
    // * This method's purpose is to create a CWE weakness ordinality object from given parameters and return it
    // *
    // * @return CWE weakness ordinality object
    // */
    //public static CWEweakOrdObj getInstance(String ordinality, String description) {

    //    return new CWEweakOrdObj(ordinality, description);
    //}

    @Override
    public String toString() {
        return "CWEweakOrdObj{" +
                "ordinality='" + ordinality + '\'' +
                ", description='" + description + '\'' +
                '}';
    }
}
