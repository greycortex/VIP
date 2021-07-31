package mitre.cpe;

import mitre.cve.CVEobject;

import javax.persistence.*;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a CPE node object (cpe_matches, vulnerable attributes of specific CPE objects, ...)
 * <p>
 * It can create a CPE node object and return it, its used in CVE objects
 * Objects can be put into database including updates (Via CVEobject.putIntoDatabase() method)
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
    @Column
    protected String operator;
    @ManyToOne
    @JoinColumn(nullable = false)
    protected CVEobject cve;
    @OneToMany(mappedBy = "node")
    protected List<CPEnodeToComplex> node_to_compl;
    @OneToMany(mappedBy = "parent")
    protected List<CPEnodeObject> children;
    @ManyToOne
    protected CPEnodeObject parent;

    @Transient
    protected List<CPEcomplexObj> compl_cpe;

    public List<CPEnodeObject> getChildren() { return children; }

    public void setChildren(List<CPEnodeObject> children) { this.children = children; }

    public CPEnodeObject getParent() { return parent; }

    public void setParent(CPEnodeObject parent) { this.parent = parent; }

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
    //                         String operator) {

    //    return new CPEnodeObject(compl_cpe, operator);
    //}

    @Override
    public String toString() {
        return "CPEnodeObject{" +
                "complex_cpe_objs=" + compl_cpe +
                ", operator=" + operator +
                ", parent=" + parent +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CPEnodeObject)) return false;
        CPEnodeObject that = (CPEnodeObject) o;
        return Objects.equals(id, that.id) && Objects.equals(compl_cpe, that.compl_cpe) && Objects.equals(operator, that.operator) && Objects.equals(parent, that.parent) && Objects.equals(cve, that.cve);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, compl_cpe, operator, parent, cve);
    }
}
