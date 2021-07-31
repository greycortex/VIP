package mitre.cwe;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CWE demonstrative example - example code object (nature attribute, language attribute, content)
 * <p>
 * Objects can be put into database including updates (Via CVEobject.putIntoDatabase() method)
 * <p>
 * //* It can create a CWE demonstrative example - example code object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "example_code")
@Table(name="example_code", schema = "mitre")
public class CWEexampCodeObj {

    public CWEexampCodeObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String nature;
    protected String language;
    @Column(length = 8191)
    protected String content;
    @ManyToOne
    protected CWEdemExObj dem_ex;

    /**
     * Copies constructor
     *
     * @param nature   nature attribute
     * @param language language attributes
     * @param content  content
     */
    public CWEexampCodeObj(String nature, String language, String content) {

        this.nature = nature;
        this.language = language;
        this.content = content;

    }

    public void setDem_ex(CWEdemExObj dem_ex) {
        this.dem_ex = dem_ex;
    }

    ///**
    // * This method's purpose is to create a CWE demonstrative example - example code object from given parameters and return it
    // *
    // * @return CWE demonstrative example - example code object
    // */
    //public static CWEexampCodeObj getInstance(String nature, String language, String content) {

    //    return new CWEexampCodeObj(nature, language, content);
    //}

    @Override
    public String toString() {
        return "CWEexampCodeObj{" +
                "nature='" + nature + '\'' +
                ", language='" + language + '\'' +
                ", language='" + content + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEexampCodeObj)) return false;
        CWEexampCodeObj that = (CWEexampCodeObj) o;
        return Objects.equals(id, that.id) && Objects.equals(nature, that.nature) && Objects.equals(language, that.language) && Objects.equals(content, that.content) && Objects.equals(dem_ex, that.dem_ex);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, nature, language, content, dem_ex);
    }
}
