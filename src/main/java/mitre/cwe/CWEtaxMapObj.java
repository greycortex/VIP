package mitre.cwe;

import mitre.capec.CAPECobject;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CWE taxonomy mapping object (name, entry name attribute, entry ID, mapping fit attribute)
 * <p>
 * //* It can create a CWE taxonomy mapping object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "taxonomy_mapping")
@Table(name="taxonomy_mapping", schema = "mitre")
public class CWEtaxMapObj {

    public CWEtaxMapObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String name;
    protected String entry_name;
    protected String entry_id;
    protected String mapping_fit;
    @ManyToOne
    protected CAPECobject capec;
    @ManyToOne
    protected CWEobject cwe;

    /**
     * Copies constructor
     *
     * @param name        name
     * @param entry_name  entry name attribute
     * @param entry_id    entry ID attribute
     * @param mapping_fit mapping fit attribute
     */
    public CWEtaxMapObj(String name, String entry_name, String entry_id, String mapping_fit) {

        this.name = name;
        this.entry_name = entry_name;
        this.entry_id = entry_id;
        this.mapping_fit = mapping_fit;

    }

    ///**
    // * This method's purpose is to create a CWE taxonomy mapping object from given parameters and return it
    // *
    // * @return CWE taxonomy mapping object
    // */
    //public static CWEtaxMapObj getInstance(String name, String entry_name, String entry_id, String mapping_fit) {

    //    return new CWEtaxMapObj(name, entry_name, entry_id, mapping_fit);
    //}

    @Override
    public String toString() {
        return "CWEtaxMapObj{" +
                "name='" + name + '\'' +
                ", entry_name='" + entry_name + '\'' +
                ", entry_id='" + entry_id + '\'' +
                ", mapping_fit='" + mapping_fit + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEtaxMapObj)) return false;
        CWEtaxMapObj that = (CWEtaxMapObj) o;
        return Objects.equals(id, that.id) && Objects.equals(name, that.name) && Objects.equals(entry_name, that.entry_name) && Objects.equals(entry_id, that.entry_id) && Objects.equals(mapping_fit, that.mapping_fit) && Objects.equals(capec, that.capec) && Objects.equals(cwe, that.cwe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, entry_name, entry_id, mapping_fit, capec, cwe);
    }
}
