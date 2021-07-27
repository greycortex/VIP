package mitre.cwe;

import mitre.capec.CAPECobject;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CWE external reference reference object (ID attribute, section attribute)
 * <p>
 * //* It can create a CWE external reference reference object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "external_ref_ref")
@Table(name="external_ref_ref", schema = "mitre")
public class CWEextRefRefObj {

    public CWEextRefRefObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String ext_ref_id;
    protected String section;
    @ManyToOne
    protected CAPECobject capec;
    @ManyToOne
    protected CWEobject cwe;
    @ManyToOne
    protected CWEdemExObj dem_ex;

    /**
     * Copies constructor
     *
     * @param ext_ref_id external reference id
     * @param section    section content
     */
    public CWEextRefRefObj(String ext_ref_id, String section) {

        this.ext_ref_id = ext_ref_id;
        this.section = section;

    }

    ///**
    // * This method's purpose is to create a CWE external reference reference object from given parameters and return it
    // *
    // * @return CWE external reference reference object
    // */
    //public static CWEextRefRefObj getInstance(String ext_ref_id, String section) {

    //    return new CWEextRefRefObj(ext_ref_id, section);
    //}

    @Override
    public String toString() {
        return "CWEextRefRefObj{" +
                "ext_ref_id='" + ext_ref_id + '\'' +
                ", section='" + section + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEextRefRefObj)) return false;
        CWEextRefRefObj that = (CWEextRefRefObj) o;
        return Objects.equals(id, that.id) && Objects.equals(ext_ref_id, that.ext_ref_id) && Objects.equals(section, that.section) && Objects.equals(capec, that.capec) && Objects.equals(cwe, that.cwe) && Objects.equals(dem_ex, that.dem_ex);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, ext_ref_id, section, capec, cwe, dem_ex);
    }
}
