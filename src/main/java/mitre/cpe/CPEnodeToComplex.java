package mitre.cpe;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents ManyToMany relation between complex CPE object and CPE node object,
 * it also has vulnerable attribute from the complex CPE object
 * <p>
 * @author Thomas Bozek (XarfNao)
 */
@Entity(name = "cve_node_compl_cpe")
@Table(name = "cve_node_compl_cpe", schema = "mitre")
public class CPEnodeToComplex {

    public CPEnodeToComplex() { } // Default constructor

    @Id
    @Column(unique = true)
    protected String id;

    @ManyToOne(cascade = CascadeType.REMOVE)
    protected CPEcomplexObj cpe;

    @ManyToOne
    protected CPEnodeObject node;

    @Column
    protected String cve_id;

    @Column
    protected Boolean vulnerable;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public CPEnodeObject getNode() {
        return node;
    }

    public void setNode(CPEnodeObject node) {
        this.node = node;
    }

    /**
     * @param id          id of the specific relation - combination of complex CPE id and CVE id
     * @param cpe         complex CPE object from the specific relation
     * @param node        node from the specific relation
     * @param cve_id      id of CVE object of the specific relation
     * @param vulnerable  vulnerable attribute of the complex CPE object from the specific relation
     */
    public CPEnodeToComplex(String id, CPEcomplexObj cpe, CPEnodeObject node, String cve_id, Boolean vulnerable) {
        this.id = id;
        this.cpe = cpe;
        this.node = node;
        this.cve_id = cve_id;
        this.vulnerable = vulnerable;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CPEnodeToComplex)) return false;
        CPEnodeToComplex that = (CPEnodeToComplex) o;
        return Objects.equals(id, that.id) && Objects.equals(cpe, that.cpe) && Objects.equals(node, that.node) && Objects.equals(cve_id, that.cve_id) && Objects.equals(vulnerable, that.vulnerable);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, cpe, node, cve_id, vulnerable);
    }
}
