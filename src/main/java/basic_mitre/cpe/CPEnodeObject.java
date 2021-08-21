package basic_mitre.cpe;

import basic_mitre.cve.CVEobject;

import javax.persistence.*;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a CPE node object (cpe_matches, vulnerable attributes of specific CPE objects, ...)
 * <p>
 * It can create a CPE node object and return it, its used in CVE objects
 * Objects can be put into database
 * <p>
 * @author Tomas Bozek (XarfNao)
 */
@Entity
@Table(name="cve_node", schema = "mitre")
public class CPEnodeObject {

    public CPEnodeObject() { } // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    @Column
    protected String operator;
    @ManyToOne
    @JoinColumn(nullable = false)
    protected CVEobject cve;
    @OneToMany(mappedBy = "node")
    protected List<CPEnodeToCPE> node_to_compl;
    @OneToMany(mappedBy = "parent")
    protected List<CPEnodeObject> children;
    @ManyToOne
    protected CPEnodeObject parent;

    @Transient
    protected List<CPEcomplexObj> compl_cpe;

    public List<CPEcomplexObj> getComplex_cpe_objs() {
        return compl_cpe;
    }

    public void setCve_obj(CVEobject cve) {
        this.cve = cve;
    }

    public Long getId() {
        return id;
    }

    /**
     * Copies constructor
     *
     * @param compl_cpe        more complex CPE (CPEcomplexObj) objects from node
     * @param operator         operator attribute of specific CPE node object
     * @param parent           parent CPE node object
     */
    public CPEnodeObject(List<CPEcomplexObj> compl_cpe,
                         String operator, CPEnodeObject parent) {

        this.compl_cpe = compl_cpe;
        this.operator = operator;
        this.parent = parent;
    }

    ///**
    // * This method's purpose is to create a CPE node object from given parameters and return it
    // *
    // * @return CPE node object
    // */
    //public static CPEnodeObject getInstance(List<CPEcomplexObj> compl_cpe,
    //                         String operator, CPEnodeObject parent) {

    //    return new CPEnodeObject(compl_cpe, operator, parent);
    //}

    @Override
    public String toString() {
        return "CPEnodeObject{" +
                "id=" + id +
                ", operator='" + operator + '\'' +
                ", cve=" + cve +
                ", node_to_compl=" + node_to_compl +
                ", children=" + children +
                ", parent=" + parent +
                ", compl_cpe=" + compl_cpe +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CPEnodeObject)) return false;
        CPEnodeObject that = (CPEnodeObject) o;
        return Objects.equals(id, that.id) && Objects.equals(operator, that.operator) && Objects.equals(cve, that.cve) && Objects.equals(node_to_compl, that.node_to_compl) && Objects.equals(children, that.children) && Objects.equals(parent, that.parent) && Objects.equals(compl_cpe, that.compl_cpe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, operator, cve, node_to_compl, children, parent, compl_cpe);
    }
}
