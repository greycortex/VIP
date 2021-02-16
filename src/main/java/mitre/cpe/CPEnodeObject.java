package mitre.cpe;

import mitre.cve.CVEobject;

import javax.persistence.*;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a CPE node object (cpe_matches, vulnerable attributes of specific CPE objects, ...)
 * <p>
 *  It can create a CPE node object and return it, its used in CVE objects
 *  It can also be put into database including updates (Via CVEobject.putIntoDatabase() method)
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity
@Table(name="cpenode")
public class CPEnodeObject {

    public CPEnodeObject() { } // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    protected Long id;
    @ManyToMany
    public List<CPEcomplexObj> complex_cpe_objs;
    @CollectionTable(name = "cpenode_operators")
    @ElementCollection(targetClass = String.class)
    protected List<String> operators;
    @CollectionTable(name = "cpenode_counts")
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CPEnodeObject)) return false;
        CPEnodeObject that = (CPEnodeObject) o;
        return Objects.equals(id, that.id) && Objects.equals(complex_cpe_objs, that.complex_cpe_objs) && Objects.equals(operators, that.operators) && Objects.equals(counts, that.counts) && Objects.equals(cve_obj, that.cve_obj);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, complex_cpe_objs, operators, counts, cve_obj);
    }
}
