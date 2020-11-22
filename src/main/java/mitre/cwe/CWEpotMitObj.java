package mitre.cwe;

import java.util.ArrayList;

/**
 * This class represents a CWE potential mitigation object (mitigation id attribute, phase attributes, strategy attribute, description attribute,
 * effectiveness attribute, effectiveness notes attribute)
 * <p>
 * //* It can create a CWE potential mitigation object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEpotMitObj {

    protected String mitigation_id;
    protected ArrayList<String> phases;
    protected String strategy;
    protected String description;
    protected String effectiveness;
    protected String effectiveness_notes;

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
    public CWEpotMitObj(String mitigation_id, ArrayList<String> phases, String strategy, String description,
                        String effectiveness, String effectiveness_notes) {

        this.mitigation_id = mitigation_id;
        this.phases = phases;
        this.strategy = strategy;
        this.description = description;
        this.effectiveness = effectiveness;
        this.effectiveness_notes = effectiveness_notes;

    }

    /**
     * This method's purpose is to create a CWE potential mitigation object from given parameters and return it
     *
     * @return CWE potential mitigation object
     */
    public static CWEpotMitObj getInstance(String mitigation_id, ArrayList<String> phases, String strategy, String description, String effectiveness,
                                           String effectiveness_notes) {

        return new CWEpotMitObj(mitigation_id, phases, strategy, description, effectiveness, effectiveness_notes);
    }

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
}
