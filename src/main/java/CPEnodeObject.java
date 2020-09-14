import java.util.ArrayList;

/**
 * This class represents a CPE node object (cpe_matches, vulnerable attributes of specific CPE objects, ...)
 *
 //* It can create a CPE node object and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CPEnodeObject {

    protected ArrayList<ArrayList<CPEobject>> cpe_matches;
    protected ArrayList<ArrayList<Boolean>> vulnerables;
    protected ArrayList<ArrayList<String>> version_start_excludings;
    protected ArrayList<ArrayList<String>> version_end_excludings;
    protected ArrayList<ArrayList<String>> version_start_includings;
    protected ArrayList<ArrayList<String>> version_end_includings;
    protected ArrayList<String> operators;

    /**
     * Copies constructor
     *
     * @param cpe_matches              CPE objects from node
     * @param vulnerables              vulnerability boolean values for each CPE object
     * @param version_start_excludings version start excluding parameters
     * @param version_end_excludings   version end excluding parameters
     * @param version_start_includings version start including parameters
     * @param version_end_includings   version end including parameters
     * @param operators                data about what operators are on which positions in CPE node
     */
    public CPEnodeObject(ArrayList<ArrayList<CPEobject>> cpe_matches, ArrayList<ArrayList<Boolean>> vulnerables,
                         ArrayList<ArrayList<String>> version_start_excludings, ArrayList<ArrayList<String>> version_end_excludings,
                         ArrayList<ArrayList<String>> version_start_includings, ArrayList<ArrayList<String>> version_end_includings,
                         ArrayList<String> operators) {

        this.cpe_matches = cpe_matches;
        this.vulnerables = vulnerables;
        this.version_start_excludings = version_start_excludings;
        this.version_end_excludings = version_end_excludings;
        this.version_start_includings = version_start_includings;
        this.version_end_includings = version_end_includings;
        this.operators = operators;
    }

    ///**
     //* This method's purpose is to create a CPE node object from given parameters and return it
     //*
     //* @return CPE node object
     //*/
    //public static CPEnodeObject createCPEnodeObj(ArrayList<ArrayList<CPEobject>> cpe_matches, ArrayList<ArrayList<Boolean>> vulnerables,
    //                                             ArrayList<ArrayList<String>> version_start_excludings, ArrayList<ArrayList<String>> version_end_excludings,
    //                                             ArrayList<ArrayList<String>> version_start_includings, ArrayList<ArrayList<String>> version_end_includings,
    //                                             ArrayList<String> operators) {
    //
    //    return new CPEnodeObject(cpe_matches, vulnerables, version_start_excludings, version_end_excludings, version_start_includings, version_end_includings,
    //            operators);
    //}

    @Override
    public String toString() {
        return "CPEnodeObject{" +
                "cpe_matches=" + cpe_matches +
                ", vulnerables=" + vulnerables +
                ", version_start_excludings=" + version_start_excludings +
                ", version_end_excludings=" + version_end_excludings +
                ", version_start_includings=" + version_start_includings +
                ", version_end_includings=" + version_end_includings +
                ", operators=" + operators +
                '}';
    }
}
