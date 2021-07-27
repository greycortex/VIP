package mitre.capec;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CAPEC skill object (level attribute, skill info)
 * <p>
 * //* It can create a CAPEC skill object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "skill")
@Table(name="skill", schema = "mitre")
public class CAPECskillObj {

    public CAPECskillObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String level;
    protected String content;
    @ManyToOne
    protected CAPECobject capec;

    /**
     * Copies constructor
     *
     * @param level         level attribute
     * @param content       skill info
     */
    public CAPECskillObj(String level, String content){

        this.level = level;
        this.content = content;

    }

    ///**
    // * This method's purpose is to create a CAPEC skill object from given parameters and return it
    // *
    // * @return CAPEC skill object
    // */
    //public static CAPECskillObj getInstance(String level, String content) {

    //    return new CAPECskillObj(level, content);
    //}

    @Override
    public String toString() {
        return "CAPECskillObj{" +
                "level='" + level + '\'' +
                ", content='" + content + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CAPECskillObj)) return false;
        CAPECskillObj that = (CAPECskillObj) o;
        return Objects.equals(id, that.id) && Objects.equals(level, that.level) && Objects.equals(content, that.content) && Objects.equals(capec, that.capec);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, level, content, capec);
    }
}
