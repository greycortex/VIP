package mitre.cwe;

/**
 * This class represents a CWE introduction (from modes of introduction) object (phase attribute, note attribute)
 * <p>
 * //* It can create a CWE introduction object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEintrModesObj {

    protected String phase;
    protected String note;

    /**
     * Copies constructor
     *
     * @param phase phase attribute
     * @param note  note attribute
     */
    public CWEintrModesObj(String phase, String note) {

        this.phase = phase;
        this.note = note;

    }

    ///**
    // * This method's purpose is to create a CWE introduction object from given parameters and return it
    // *
    // * @return CWE introduction object
    // */
    //public static CWEintrModesObj getInstance(String phase, String note) {

    //    return new CWEintrModesObj(phase, note);
    //}

    @Override
    public String toString() {
        return "CWEintrModesObj{" +
                "phase='" + phase + '\'' +
                ", note='" + note + '\'' +
                '}';
    }
}
