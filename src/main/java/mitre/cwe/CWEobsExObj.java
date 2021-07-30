package mitre.cwe;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CWE observed example object (reference attribute, description attribute, link attribute)
 * <p>
 * //* It can create a CWE observed example object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "observed_example")
@Table(name="observed_example", schema = "mitre")
public class CWEobsExObj {

    public CWEobsExObj() {} // deafult constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String reference;
    @Column(length = 4095)
    protected String description;
    @Column(length = 4095)
    protected String link;
    @ManyToOne
    protected CWEobject cwe;

    /**
     * Copies constructor
     *
     * @param reference   reference attribute
     * @param description description attribute
     * @param link        link attribute
     */
    public CWEobsExObj(String reference, String description, String link) {

        this.reference = reference;
        this.description = description;
        this.link = link;

    }

    ///**
    // * This method's purpose is to create a CWE observed example object from given parameters and return it
    // *
    // * @return CWE observed example object
    // */
    //public static CWEobsExObj getInstance(String reference, String description, String link) {

    //    return new CWEobsExObj(reference, description, link);
    //}

    @Override
    public String toString() {
        return "CWEobsExObj{" +
                "reference='" + reference + '\'' +
                ", description='" + description + '\'' +
                ", link='" + link + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEobsExObj)) return false;
        CWEobsExObj that = (CWEobsExObj) o;
        return Objects.equals(id, that.id) && Objects.equals(reference, that.reference) && Objects.equals(description, that.description) && Objects.equals(link, that.link) && Objects.equals(cwe, that.cwe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, reference, description, link, cwe);
    }
}
