package mitre.capec;

import javax.persistence.*;
import java.util.List;
import java.util.Objects;

/**
 * This class represents an attack step object (step attribute, phase attribute, description attribute, technique attributes)
 * <p>
 * //* It can create a CAPEC attack step object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "attack_step")
@Table(name="attack_step", schema = "mitre")
public class CAPECattStepObj {

    public CAPECattStepObj() { } // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String step;
    protected String phase;
    protected String description;
    @Column(length = 8191)
    @CollectionTable(name = "technique", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> techniques;
    @ManyToOne
    protected CAPECobject capec;

    /**
     * Copies constructor
     *
     * @param step         step attribute
     * @param phase        phase attribute
     * @param description  description attribute
     * @param techniques   technique attributes
     */
    public CAPECattStepObj(String step, String phase, String description, List<String> techniques){

        this.step = step;
        this.phase = phase;
        this.description = description;
        this.techniques = techniques;

    }

    ///**
    // * This method's purpose is to create an attack step object from given parameters and return it
    // *
    // * @return attack step object
    // */
    //public static CAPECattStepObj getInstance(String step, String phase, String description, List<String> techniques) {

    //    return new CAPECattStepObj(step, phase, description, techniques);
    //}

    @Override
    public String toString() {
        return "CAPECattStepObj{" +
                "step='" + step + '\'' +
                ", phase='" + phase + '\'' +
                ", description='" + description + '\'' +
                ", techniques=" + techniques +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CAPECattStepObj)) return false;
        CAPECattStepObj that = (CAPECattStepObj) o;
        return Objects.equals(id, that.id) && Objects.equals(step, that.step) && Objects.equals(phase, that.phase) && Objects.equals(description, that.description) && Objects.equals(techniques, that.techniques) && Objects.equals(capec, that.capec);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, step, phase, description, techniques, capec);
    }
}
