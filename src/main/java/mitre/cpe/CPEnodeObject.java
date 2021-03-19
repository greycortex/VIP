package mitre.cpe;

import mitre.cve.CVEobject;

import javax.persistence.*;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a CPE node object (cpe_matches, vulnerable attributes of specific CPE objects, ...)
 * <p>
 * It can create a CPE node object and return it, its used in CVE objects
 * It can also be put into database including updates (Via CVEobject.putIntoDatabase() method)
 * <p>
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "node")
@Table(name="node", schema = "mitre")
public class CPEnodeObject {

    public CPEnodeObject() { } // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    @CollectionTable(name = "node_operators", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> operators;
    @CollectionTable(name = "node_counts", schema = "mitre")
    @ElementCollection(targetClass = Integer.class)
    protected List<Integer> counts;
    @ManyToOne
    @JoinColumn(nullable = false)
    protected CVEobject cve;
    @OneToMany(mappedBy = "node")
    protected List<CPEnodeToComplex> node_to_compl;

    @Transient
    protected List<CPEcomplexObj> compl_cpe;

    public List<CPEcomplexObj> getComplex_cpe_objs() {
        return compl_cpe;
    }

    public void setComplex_cpe_objs(List<CPEcomplexObj> compl_cpe) {
        this.compl_cpe = compl_cpe;
    }

    public List<CPEnodeToComplex> getNode_to_compl() {
        return node_to_compl;
    }

    public void setNode_to_compl(List<CPEnodeToComplex> node_to_compl) {
        this.node_to_compl = node_to_compl;
    }

    public CVEobject getCve_obj() {
        return cve;
    }

    public void setCve_obj(CVEobject cve) {
        this.cve = cve;
    }

    /**
     * Copies constructor
     *
     * @param compl_cpe        more complex CPE (CPEcomplexObj) objects from node
     * @param operators        data about what operators are on which positions in CPE node
     * @param counts           counts of CPE objects under one operator
     */
    public CPEnodeObject(List<CPEcomplexObj> compl_cpe,
                         List<String> operators, List<Integer> counts) {

        this.compl_cpe = compl_cpe;
        this.operators = operators;
        this.counts = counts;
    }

    ///**
    // * This method's purpose is to create a CPE node object from given parameters and return it
    // *
    // * @return CPE node object
    // */
    //public static CPEnodeObject getInstance(List<CPEcomplexObj> compl_cpe,
    //                                        List<String> operators, List<Integer> counts) {

    //    return new CPEnodeObject(compl_cpe, operators, counts);
    //}

    @Override
    public String toString() {
        return "CPEnodeObject{" +
                "complex_cpe_objs=" + compl_cpe +
                ", operators=" + operators +
                ", counts=" + counts +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CPEnodeObject)) return false;
        CPEnodeObject that = (CPEnodeObject) o;
        return Objects.equals(id, that.id) && Objects.equals(compl_cpe, that.compl_cpe) && Objects.equals(operators, that.operators) && Objects.equals(counts, that.counts) && Objects.equals(cve, that.cve);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, compl_cpe, operators, counts, cve);
    }
}
