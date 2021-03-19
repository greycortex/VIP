package mitre.cpe;

import javax.persistence.*;

/**
 * This class represents ManyToMany relation between complex CPE object and CPE node object,
 * it also has vulnerable attribute from the complex CPE object
 * <p>
 * @author Thomas Bozek (XarfNao)
 */
@Entity(name = "node_compl_cpe")
@Table(name = "node_compl_cpe", schema = "mitre")
public class CPEnodeToComplex {

    public CPEnodeToComplex() { } // Default constructor

    @Id
    @Column(unique = true)
    protected String id;

    @ManyToOne
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

    public CPEcomplexObj getCpe() {
        return cpe;
    }

    public void setCpe(CPEcomplexObj cpe) {
        this.cpe = cpe;
    }

    public CPEnodeObject getNode() {
        return node;
    }

    public String getCve_id() { return cve_id; }

    public void setCve_id(String cve_id) { this.cve_id = cve_id; }

    public void setNode(CPEnodeObject node) {
        this.node = node;
    }

    public Boolean getVulnerable() {
        return vulnerable;
    }

    public void setVulnerable(Boolean vulnerable) {
        this.vulnerable = vulnerable;
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
}
