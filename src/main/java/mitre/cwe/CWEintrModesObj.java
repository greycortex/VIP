package mitre.cwe;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CWE introduction (from modes of introduction) object (phase attribute, note attribute)
 * <p>
 * Objects can be put into database including updates (Via CVEobject.putIntoDatabase() method)
 * <p>
 * //* It can create a CWE introduction object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "cwe_introduction")
@Table(name="cwe_introduction", schema = "mitre")
public class CWEintrModesObj {

    public CWEintrModesObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String phase;
    @Column(length = 8191)
    protected String note;
    @ManyToOne
    protected CWEobject cwe;

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

    public void setCwe(CWEobject cwe) {
        this.cwe = cwe;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEintrModesObj)) return false;
        CWEintrModesObj that = (CWEintrModesObj) o;
        return Objects.equals(id, that.id) && Objects.equals(phase, that.phase) && Objects.equals(note, that.note) && Objects.equals(cwe, that.cwe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, phase, note, cwe);
    }
}
