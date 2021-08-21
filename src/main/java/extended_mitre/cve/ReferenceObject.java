package extended_mitre.cve;

import javax.persistence.*;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a reference object which can be found in CVE object
 * <p>
 * Objects can be put into database including updates (Via CVEobject.putIntoDatabase() method)
 * <p>
 * //* It can create a reference object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity
@Table(name="cve_reference", schema = "mitre")
public class ReferenceObject {

    public ReferenceObject() { } // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    @Column(length = 8191)
    protected String url;
    @Column(length = 8191)
    protected String name;
    protected String refsource;
    @Column(name = "tag")
    @CollectionTable(name = "ref_tags", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> tags;
    @ManyToOne
    @JoinColumn(nullable = false)
    protected CVEobject cve;

    public CVEobject getCve_obj() {
        return cve;
    }

    public void setCve_obj(CVEobject cve) {
        this.cve = cve;
    }

    /**
     * Copies constructor
     *
     * @param url       reference url
     * @param name      name of the reference
     * @param refsource refsource attribute
     * @param tags      tags of the reference
     */
    public ReferenceObject(String url, String name, String refsource, List<String> tags) {

        this.url = url;
        this.name = name;
        this.refsource = refsource;
        this.tags = tags;
    }

    ///**
    // * This method's purpose is to create a reference object from given parameters and return it
    // *
    // * @return reference object
    // */
    //public static ReferenceObject getInstance(String url, String name, String refsource, List<String> tags) {

    //    return new ReferenceObject(url, name, refsource, tags);
    //}

    @Override
    public String toString() {
        return "ReferenceObject{" +
                "url='" + url + '\'' +
                ", name='" + name + '\'' +
                ", refsource='" + refsource + '\'' +
                ", tags=" + tags +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ReferenceObject)) return false;
        ReferenceObject that = (ReferenceObject) o;
        return Objects.equals(id, that.id) && Objects.equals(url, that.url) && Objects.equals(name, that.name) && Objects.equals(refsource, that.refsource) && Objects.equals(tags, that.tags) && Objects.equals(cve, that.cve);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, url, name, refsource, tags, cve);
    }
}
