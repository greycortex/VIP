package mitre.cve;

import mitre.cpe.CPEcomplexObj;

import javax.persistence.*;

/**
 * This class represents ManyToMany relation between complex CPE object and CVE object,
 * it also has vulnerable attribute from the complex CPE object
 * <p>
 * Its created only if the vulnerable attribute is true
 * <p>
 * @author Thomas Bozek (XarfNao)
 */
@Entity(name = "cve_cpe")
@Table(name = "cve_cpe", schema = "mitre")
public class CVEtoCPE {

    public CVEtoCPE(){ } // default constructor

    @Id
    @Column(unique = true)
    protected String id;

    @ManyToOne
    protected CPEcomplexObj cpe;

    @ManyToOne
    protected CVEobject cve;

    @Column
    protected Boolean vulnerable;

    public CPEcomplexObj getCpe() {
        return cpe;
    }

    public void setCpe(CPEcomplexObj cpe) {
        this.cpe = cpe;
    }

    public CVEobject getCve() {
        return cve;
    }

    public void setCve(CVEobject cve) {
        this.cve = cve;
    }

    public Boolean getVulnerable() {
        return vulnerable;
    }

    public void setVulnerable(Boolean vulnerable) {
        this.vulnerable = vulnerable;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    /**
     * @param id          combination of CVE id and id of the complex CPE object
     * @param cpe         specific complex CPE object
     * @param cve         specific CVE object
     * @param vulnerable  vulnerable attribute of the complex CPE object - always true
     */
    public CVEtoCPE(String id, CPEcomplexObj cpe, CVEobject cve, Boolean vulnerable) {
        this.id = id;
        this.cpe = cpe;
        this.cve = cve;
        this.vulnerable = vulnerable;
    }
}
