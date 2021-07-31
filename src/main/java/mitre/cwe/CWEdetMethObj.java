package mitre.cwe;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CWE detection method object (method id attribute, method attribute, description attribute,
 * effectiveness attribute, effectiveness notes attribute)
 * <p>
 * Objects can be put into database including updates (Via CVEobject.putIntoDatabase() method)
 * <p>
 * //* It can create a CWE detection method object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "detection_method")
@Table(name="detection_method", schema = "mitre")
public class CWEdetMethObj {

    public CWEdetMethObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String method_id;
    protected String method;
    @Column(length = 8191)
    protected String description;
    protected String effectiveness;
    @Column(length = 8191)
    protected String effectiveness_notes;
    @ManyToOne
    protected CWEobject cwe;


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

    public void setCwe(CWEobject cwe) {
        this.cwe = cwe;
    }

    ///**
    // * This method's purpose is to create a CWE detection method object from given parameters and return it
    // *
    // * @return CWE detection method object
    // */
    //public static CWEdetMethObj getInstance(String method_id, String method, String description, String effectiveness, String effectiveness_notes) {

    //    return new CWEdetMethObj(method_id, method, description, effectiveness, effectiveness_notes);
    //}

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEdetMethObj)) return false;
        CWEdetMethObj that = (CWEdetMethObj) o;
        return Objects.equals(id, that.id) && Objects.equals(method_id, that.method_id) && Objects.equals(method, that.method) && Objects.equals(description, that.description) && Objects.equals(effectiveness, that.effectiveness) && Objects.equals(effectiveness_notes, that.effectiveness_notes) && Objects.equals(cwe, that.cwe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, method_id, method, description, effectiveness, effectiveness_notes, cwe);
    }
}
