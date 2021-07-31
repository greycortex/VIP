package mitre.cwe;

import mitre.capec.CAPECobject;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CWE alternate term object (term attribute, description attribute)
 * <p>
 * //* It can create a CWE alternate term object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "alternate_term")
@Table(name="alternate_term", schema = "mitre")
public class CWEalterTermObj {

    public CWEalterTermObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String term;
    @Column(length = 8191)
    protected String description;
    @ManyToOne
    protected CAPECobject capec;
    @ManyToOne
    protected CWEobject cwe;

    /**
     * Copies constructor
     *
     * @param term        term attribute
     * @param description description attribute
     */
    public CWEalterTermObj(String term, String description) {

        this.term = term;
        this.description = description;

    }

    public void setCwe(CWEobject cwe) {
        this.cwe = cwe;
    }

    public void setCapec(CAPECobject capec) {
        this.capec = capec;
    }

    ///**
    // * This method's purpose is to create a CWE alternate term object from given parameters and return it
    // *
    // * @return CWE alternate term object
    // */
    //public static CWEalterTermObj getInstance(String term, String description) {

    //    return new CWEalterTermObj(term, description);
    //}

    @Override
    public String toString() {
        return "CWEalterTermObj{" +
                "term='" + term + '\'' +
                ", description='" + description + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEalterTermObj)) return false;
        CWEalterTermObj that = (CWEalterTermObj) o;
        return Objects.equals(id, that.id) && Objects.equals(term, that.term) && Objects.equals(description, that.description) && Objects.equals(capec, that.capec) && Objects.equals(cwe, that.cwe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, term, description, capec, cwe);
    }
}
