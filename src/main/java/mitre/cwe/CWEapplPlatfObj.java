package mitre.cwe;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CWE applicable platform object (type attribute, class attribute, name attribute, prevalence attribute)
 * <p>
 * Objects can be put into database including updates (Via CVEobject.putIntoDatabase() method)
 * <p>
 * //* It can create a CWE applicable platform object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "applicable_platform")
@Table(name="applicable_platform", schema = "mitre")
public class CWEapplPlatfObj {

    public CWEapplPlatfObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String type;
    protected String platform_class;
    protected String name;
    protected String prevalence;
    @ManyToOne
    protected CWEobject cwe;

    /**
     * Copies constructor
     *
     * @param type           type attribute
     * @param platform_class platform_class attribute
     * @param name           name attribute
     * @param prevalence     prevalence attribute
     */
    public CWEapplPlatfObj(String type, String platform_class, String name, String prevalence) {

        this.type = type;
        this.platform_class = platform_class;
        this.name = name;
        this.prevalence = prevalence;

    }

    public void setCwe(CWEobject cwe) {
        this.cwe = cwe;
    }

    ///**
    // * This method's purpose is to create a CWE applicable platform object from given parameters and return it
    // *
    // * @return CWE applicable platform object
    // */
    //public static CWEapplPlatfObj getInstance(String type, String platform_class, String name, String prevalence) {

    //    return new CWEapplPlatfObj(type, platform_class, name, prevalence);
    //}

    @Override
    public String toString() {
        return "CWEapplPlatfObj{" +
                "type='" + type + '\'' +
                ", platform_class='" + platform_class + '\'' +
                ", name='" + name + '\'' +
                ", prevalence='" + prevalence + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEapplPlatfObj)) return false;
        CWEapplPlatfObj that = (CWEapplPlatfObj) o;
        return Objects.equals(id, that.id) && Objects.equals(type, that.type) && Objects.equals(platform_class, that.platform_class) && Objects.equals(name, that.name) && Objects.equals(prevalence, that.prevalence) && Objects.equals(cwe, that.cwe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, type, platform_class, name, prevalence, cwe);
    }
}
