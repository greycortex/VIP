package extended_mitre.cwe;

import javax.persistence.*;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a CWE potential mitigation object (mitigation id attribute, phase attributes, strategy attribute, description attribute,
 * effectiveness attribute, effectiveness notes attribute)
 * <p>
 * Objects can be put into database
 * <p>
 * It can create a CWE potential mitigation object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "pot_mit")
@Table(name="cwe_potential_mitigation", schema = "mitre")
public class CWEpotMitObj {

    public CWEpotMitObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String mitigation_id;
    @Column(name = "phase")
    @CollectionTable(name = "pot_mit_phases", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> phases;
    protected String strategy;
    @Column(length = 8191)
    protected String description;
    protected String effectiveness;
    @Column(length = 8191)
    protected String effectiveness_notes;
    @ManyToOne
    protected CWEobject cwe;

    /**
     * Copies constructor
     *
     * @param mitigation_id       mitigation id attribute
     * @param phases              phase attributes
     * @param strategy            strategy attribute
     * @param description         description attribute
     * @param effectiveness       effectiveness attribute
     * @param effectiveness_notes effectiveness notes attribute
     */
    public CWEpotMitObj(String mitigation_id, List<String> phases, String strategy, String description,
                        String effectiveness, String effectiveness_notes) {

        this.mitigation_id = mitigation_id;
        this.phases = phases;
        this.strategy = strategy;
        this.description = description;
        this.effectiveness = effectiveness;
        this.effectiveness_notes = effectiveness_notes;

    }

    public void setCwe(CWEobject cwe) {
        this.cwe = cwe;
    }

    ///**
    // * This method's purpose is to create a CWE potential mitigation object from given parameters and return it
    // *
    // * @return CWE potential mitigation object
    // */
    //public static CWEpotMitObj getInstance(String mitigation_id, List<String> phases, String strategy, String description, String effectiveness,
    //                                       String effectiveness_notes) {

    //    return new CWEpotMitObj(mitigation_id, phases, strategy, description, effectiveness, effectiveness_notes);
    //}

    @Override
    public String toString() {
        return "CWEpotMitObj{" +
                "mitigation_id=" + mitigation_id +
                "phases=" + phases +
                ", strategy='" + strategy + '\'' +
                ", description='" + description + '\'' +
                ", effectiveness='" + effectiveness + '\'' +
                ", effectiveness_notes='" + effectiveness_notes + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEpotMitObj)) return false;
        CWEpotMitObj that = (CWEpotMitObj) o;
        return Objects.equals(mitigation_id, that.mitigation_id) && Objects.equals(phases, that.phases) && Objects.equals(strategy, that.strategy) && Objects.equals(description, that.description) && Objects.equals(effectiveness, that.effectiveness) && Objects.equals(effectiveness_notes, that.effectiveness_notes) && Objects.equals(cwe, that.cwe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mitigation_id, phases, strategy, description, effectiveness, effectiveness_notes);
    }
}
