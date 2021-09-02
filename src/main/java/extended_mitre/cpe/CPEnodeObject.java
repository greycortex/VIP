package extended_mitre.cpe;

import extended_mitre.cve.CVEobject;

import javax.persistence.*;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a CPE node object (cpe_matches, vulnerable attributes of specific CPE objects, ...)
 * <p>
 * It can create a CPE node object and return it, its used in CVE objects
 * Objects can be put into database including quick updates
 * <p>
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "cve_node")
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

    public String getOperator() {
        return operator;
    }

    public void setOperator(String operator) {
        this.operator = operator;
    }

    public List<CPEnodeToCPE> getNode_to_compl() {
        return node_to_compl;
    }

    public void setNode_to_compl(List<CPEnodeToCPE> node_to_compl) {
        this.node_to_compl = node_to_compl;
    }

    public List<CPEnodeObject> getChildren() {
        return children;
    }

    public void setChildren(List<CPEnodeObject> children) {
        this.children = children;
    }

    public CPEnodeObject getParent() {
        return parent;
    }

    public void setParent(CPEnodeObject parent) {
        this.parent = parent;
    }

    /**
     * Copies constructor
     *
     * @param compl_cpe        more complex CPE (CPEcomplexObj) objects from node
     * @param operator         operator attribute of specific CPE node object
     * @param parent           parent CPE node object
     * @param node_to_compl    related CVE to CPE relations
     * @param children         children CPE node objects
     */
    public CPEnodeObject(List<CPEcomplexObj> compl_cpe,
                         String operator, CPEnodeObject parent, List<CPEnodeToCPE> node_to_compl, List<CPEnodeObject> children) {

        this.compl_cpe = compl_cpe;
        this.operator = operator;
        this.parent = parent;
        this.node_to_compl = node_to_compl;
        this.children = children;
    }

    ///**
    // * This method's purpose is to create a CPE node object from given parameters and return it
    // *
    // * @return CPE node object
    // */
    //public static CPEnodeObject getInstance(List<CPEcomplexObj> compl_cpe,
    //                         String operator, CPEnodeObject parent, List<CPEnodeToCPE> node_to_compl, List<CPEnodeObject> children) {

    //    return new CPEnodeObject(compl_cpe, operator, parent, node_to_compl, children);
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
        return Objects.equals(operator, that.operator) && Objects.equals(parent, that.parent) && Objects.equals(node_to_compl, that.node_to_compl);
    }

    @Override
    public int hashCode() {
        return Objects.hash(operator, node_to_compl, parent);
    }
}
