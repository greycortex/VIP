package mitre.cwe;

import mitre.capec.CAPECobject;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CWE note object (type attribute, content of the note)
 * <p>
 * Objects can be put into database including updates (Via CVEobject.putIntoDatabase() method)
 * <p>
 * //* It can create a CWE note object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "note")
@Table(name="note", schema = "mitre")
public class CWEnoteObj {

    public CWEnoteObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String type;
    @Column(length = 8191)
    protected String note_content;
    @ManyToOne
    protected CAPECobject capec;
    @ManyToOne
    protected CWEobject cwe;

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

    public void setCwe(CWEobject cwe) {
        this.cwe = cwe;
    }

    public void setCapec(CAPECobject capec) {
        this.capec = capec;
    }

    ///**
    // * This method's purpose is to create a CWE note object from given parameters and return it
    // *
    // * @return CWE note object
    // */
    //public static CWEnoteObj getInstance(String type, String note_content) {

    //    return new CWEnoteObj(type, note_content);
    //}

    @Override
    public String toString() {
        return "CWEnoteObj{" +
                "type='" + type + '\'' +
                ", note_content='" + note_content + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEnoteObj)) return false;
        CWEnoteObj that = (CWEnoteObj) o;
        return Objects.equals(id, that.id) && Objects.equals(type, that.type) && Objects.equals(note_content, that.note_content) && Objects.equals(capec, that.capec) && Objects.equals(cwe, that.cwe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, type, note_content, capec, cwe);
    }
}
