package mitre.cwe;

import mitre.capec.CAPECobject;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Objects;

/**
 * This class represents a CWE external reference reference object (section attribute, reference id attribute)
 * <p>
 * Objects can be put into database including updates (Via CVEobject.putIntoDatabase() method)
 * <p>
 * //* It can create a CWE external reference reference object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "external_ref_ref")
@Table(name="external_ref_ref", schema = "mitre")
public class CWEextRefRefObj implements Serializable {

    public CWEextRefRefObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String section;
    @ManyToOne
    protected CAPECobject capec;
    @ManyToOne
    protected CWEobject cwe;
    @ManyToOne
    protected CWEdemExObj dem_ex;
    @ManyToOne
    protected CWEextRefObj ext_ref;

    /**
     * Copies constructor
     *
     * @param ext_ref    External Reference object which is referred to
     * @param section    section content
     */
    public CWEextRefRefObj(CWEextRefObj ext_ref, String section) {
        this.ext_ref = ext_ref;
        this.section = section;
    }

    public CWEextRefObj getExt_ref() {
        return ext_ref;
    }

    public void setExt_ref(CWEextRefObj ext_ref) {
        this.ext_ref = ext_ref;
    }

    public void setCapec(CAPECobject capec) {
        this.capec = capec;
    }

    public void setCwe(CWEobject cwe) {
        this.cwe = cwe;
    }

    public void setDem_ex(CWEdemExObj dem_ex) {
        this.dem_ex = dem_ex;
    }

    ///**
    // * This method's purpose is to create a CWE external reference reference object from given parameters and return it
    // *
    // * @return CWE external reference reference object
    // */
    //public static CWEextRefRefObj getInstance(CWEextRefObj ext_ref, String section) {

    //    return new CWEextRefRefObj(ext_ref, section);
    //}


    @Override
    public String toString() {
        return "CWEextRefRefObj{" +
                ", section='" + section + '\'' +
                ", ext_ref=" + ext_ref +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEextRefRefObj)) return false;
        CWEextRefRefObj that = (CWEextRefRefObj) o;
        return Objects.equals(id, that.id) && Objects.equals(section, that.section) && Objects.equals(capec, that.capec) && Objects.equals(cwe, that.cwe) && Objects.equals(dem_ex, that.dem_ex) && Objects.equals(ext_ref, that.ext_ref);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, section, capec, cwe, dem_ex, ext_ref);
    }
}
