package mitre.cpe;

import mitre.cve.CVEobject;

import javax.persistence.*;
import java.util.List;

/**
 * This class represents a CPE node object (cpe_matches, vulnerable attributes of specific CPE objects, ...)
 * <p>
 * //* It can create a CPE node object and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity
@Table(name="cpenodeobject")
public class CPEnodeObject {

    public CPEnodeObject(){ } // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    protected Long id;
    @ManyToMany
    public List<CPEcomplexObj> complex_cpe_objs;
    @Column
    @ElementCollection(targetClass = String.class)
    protected List<String> operators;
    @Column
    @ElementCollection(targetClass = Integer.class)
    protected List<Integer> counts;
    @ManyToOne
    @JoinColumn(nullable = false)
    public CVEobject cve_obj;

    /**
     * Copies constructor
     *
     * @param complex_cpe_objs more complex CPE (CPEcomplexObj) objects from node
     * @param operators        data about what operators are on which positions in CPE node
     * @param counts           counts of CPE objects under one operator
     */
    public CPEnodeObject(List<CPEcomplexObj> complex_cpe_objs,
                         List<String> operators, List<Integer> counts) {

        this.complex_cpe_objs = complex_cpe_objs;
        this.operators = operators;
        this.counts = counts;
    }

    ///**
    // * This method's purpose is to create a CPE node object from given parameters and return it
    // *
    // * @return CPE node object
    // */
    //public static CPEnodeObject getInstance(List<CPEcomplexObj> complex_cpe_objs,
    //                                        List<String> operators, List<Integer> counts) {

    //    return new CPEnodeObject(complex_cpe_objs, operators, counts);
    //}

    @Override
    public String toString() {
        return "CPEnodeObject{" +
                "complex_cpe_objs=" + complex_cpe_objs +
                ", operators=" + operators +
                ", counts=" + counts +
                '}';
    }
}
