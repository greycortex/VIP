import java.util.ArrayList;

/**
 * This class represents a CPE node object (cpe_matches, vulnerable attributes of specific CPE objects, ...)
 * <p>
 * //* It can create a CPE node object and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CPEnodeObject {

    protected ArrayList<ArrayList<CPEcomplexObj>> complex_cpe_objs;
    protected ArrayList<String> operators;

    /**
     * Copies constructor
     *
     * @param complex_cpe_objs more complex CPE (CPEcomplexObj) objects from node
     * @param operators        data about what operators are on which positions in CPE node
     */
    public CPEnodeObject(ArrayList<ArrayList<CPEcomplexObj>> complex_cpe_objs,
                         ArrayList<String> operators) {

        this.complex_cpe_objs = complex_cpe_objs;
        this.operators = operators;
    }

    /**
     * This method's purpose is to create a CPE node object from given parameters and return it
     *
     * @return CPE node object
     */
    public static CPEnodeObject getInstance(ArrayList<ArrayList<CPEcomplexObj>> complex_cpe_objs,
                                            ArrayList<String> operators) {

        return new CPEnodeObject(complex_cpe_objs, operators);
    }

    @Override
    public String toString() {
        return "CPEnodeObject{" +
                "complex_cpe_objs=" + complex_cpe_objs +
                ", operators=" + operators +
                '}';
    }
}
