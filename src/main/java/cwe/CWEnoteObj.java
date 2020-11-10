package cwe;

/**
 * This class represents a CWE note object (type attribute, content of the note)
 * <p>
 * //* It can create a CWE note object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEnoteObj {

    protected String type;
    protected String note_content;

    /**
     * Copies constructor
     *
     * @param type         type attribute
     * @param note_content note content
     */
    public CWEnoteObj(String type, String note_content) {

        this.type = type;
        this.note_content = note_content;

    }

    /**
     * This method's purpose is to create a CWE note object from given parameters and return it
     *
     * @return CWE note object
     */
    public static CWEnoteObj getInstance(String type, String note_content) {

        return new CWEnoteObj(type, note_content);
    }

    @Override
    public String toString() {
        return "CWEnoteObj{" +
                "type='" + type + '\'' +
                ", note_content='" + note_content + '\'' +
                '}';
    }
}
