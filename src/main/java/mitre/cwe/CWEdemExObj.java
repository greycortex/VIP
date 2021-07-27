package mitre.cwe;

import javax.persistence.*;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a CWE demonstrative example object (nature attribute, language attribute, content)
 * <p>
 * //* It can create a CWE demonstrative example object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "demonstrative_examp")
@Table(name="demonstrative_examp", schema = "mitre")
public class CWEdemExObj {

    public CWEdemExObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String intro_text;
    @OneToMany(mappedBy = "dem_ex")
    protected List<CWEexampCodeObj> dem_ex_ex_codes;
    @Column(length = 8191)
    @CollectionTable(name = "body_text", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> dem_ex_body_texts;
    @OneToMany(mappedBy = "dem_ex")
    protected List<CWEextRefRefObj> dem_ex_ext_ref_refs;
    @ManyToOne
    protected CWEobject cwe;

    /**
     * Copies constructor
     *
     * @param intro_text          intro text attribute
     * @param dem_ex_ex_codes     example code objects
     * @param dem_ex_body_texts   body text attributes
     * @param dem_ex_ext_ref_refs external reference reference objects
     */
    public CWEdemExObj(String intro_text, List<CWEexampCodeObj> dem_ex_ex_codes, List<String> dem_ex_body_texts,
                       List<CWEextRefRefObj> dem_ex_ext_ref_refs) {

        this.intro_text = intro_text;
        this.dem_ex_ex_codes = dem_ex_ex_codes;
        this.dem_ex_body_texts = dem_ex_body_texts;
        this.dem_ex_ext_ref_refs = dem_ex_ext_ref_refs;

    }

    ///**
    // * This method's purpose is to create a CWE demonstrative example object from given parameters and return it
    // *
    // * @return CWE demonstrative example object
    // */
    //public static CWEdemExObj getInstance(String intro_text, List<CWEexampCodeObj> dem_ex_ex_codes, List<String> dem_ex_body_texts,
    //                                      List<CWEextRefRefObj> dem_ex_ext_ref_refs) {

    //    return new CWEdemExObj(intro_text, dem_ex_ex_codes, dem_ex_body_texts, dem_ex_ext_ref_refs);
    //}

    @Override
    public String toString() {
        return "CWEdemExObj{" +
                "intro_text='" + intro_text + '\'' +
                ", dem_ex_ex_codes=" + dem_ex_ex_codes +
                ", dem_ex_body_texts=" + dem_ex_body_texts +
                ", dem_ex_ext_ref_refs=" + dem_ex_ext_ref_refs +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEdemExObj)) return false;
        CWEdemExObj that = (CWEdemExObj) o;
        return Objects.equals(id, that.id) && Objects.equals(intro_text, that.intro_text) && Objects.equals(dem_ex_ex_codes, that.dem_ex_ex_codes) && Objects.equals(dem_ex_body_texts, that.dem_ex_body_texts) && Objects.equals(dem_ex_ext_ref_refs, that.dem_ex_ext_ref_refs) && Objects.equals(cwe, that.cwe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, intro_text, dem_ex_ex_codes, dem_ex_body_texts, dem_ex_ext_ref_refs, cwe);
    }
}
