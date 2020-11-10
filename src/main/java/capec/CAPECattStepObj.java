package capec;

import java.util.ArrayList;

/**
 * This class represents an attack step object (step attribute, phase attribute, description attribute, technique attributes)
 * <p>
 * //* It can create a CAPEC attack step object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CAPECattStepObj {

    protected String step;
    protected String phase;
    protected String description;
    protected ArrayList<String> techniques;

    /**
     * Copies constructor
     *
     * @param step         step attribute
     * @param phase        phase attribute
     * @param description  description attribute
     * @param techniques   technique attributes
     */
    public CAPECattStepObj(String step, String phase, String description, ArrayList<String> techniques){

        this.step = step;
        this.phase = phase;
        this.description = description;
        this.techniques = techniques;

    }

    /**
     * This method's purpose is to create an attack step object from given parameters and return it
     *
     * @return attack step object
     */
    public static CAPECattStepObj getInstance(String step, String phase, String description, ArrayList<String> techniques) {

        return new CAPECattStepObj(step, phase, description, techniques);
    }

    @Override
    public String toString() {
        return "CAPECattStepObj{" +
                "step='" + step + '\'' +
                ", phase='" + phase + '\'' +
                ", description='" + description + '\'' +
                ", techniques=" + techniques +
                '}';
    }
}
