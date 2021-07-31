package mitre.cwe;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CWE relation object (nature attribute, CWE code (ID) of related CWE, view_id attribute, ordinal attribute)
 * <p>
 * //* It can create a CWE relation object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "cwe_relation")
@Table(name="cwe_relation", schema = "mitre")
public class CWErelationObj {

    public CWErelationObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String nature;
    protected String related_cwe_id;
    protected String view_id;
    protected String ordinal;
    @ManyToOne
    protected CWEobject cwe;

    /**
     * Copies constructor
     *
     * @param nature         nature attribute
     * @param related_cwe_id CWE code (ID) of related CWE
     * @param view_id        view_id attribute
     * @param ordinal        ordinal attribute
     */
    public CWErelationObj(String nature, String related_cwe_id, String view_id, String ordinal) {

        this.nature = nature;
        this.related_cwe_id = related_cwe_id;
        this.view_id = view_id;
        this.ordinal = ordinal;

    }

    public void setCwe(CWEobject cwe) {
        this.cwe = cwe;
    }

    ///**
    // * This method's purpose is to create a CWE relation object from given parameters and return it
    // *
    // * @return CWE relation object
    // */
    //public static CWErelationObj getInstance(String nature, String related_cwe_id, String view_id, String ordinal) {

    //    return new CWErelationObj(nature, related_cwe_id, view_id, ordinal);
    //}

    @Override
    public String toString() {
        return "CWErelationObj{" +
                "nature='" + nature + '\'' +
                ", related_cwe_id='" + related_cwe_id + '\'' +
                ", view_id='" + view_id + '\'' +
                ", ordinal='" + ordinal + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWErelationObj)) return false;
        CWErelationObj that = (CWErelationObj) o;
        return Objects.equals(id, that.id) && Objects.equals(nature, that.nature) && Objects.equals(related_cwe_id, that.related_cwe_id) && Objects.equals(view_id, that.view_id) && Objects.equals(ordinal, that.ordinal) && Objects.equals(cwe, that.cwe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, nature, related_cwe_id, view_id, ordinal, cwe);
    }
}
