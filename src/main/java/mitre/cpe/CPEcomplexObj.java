package mitre.cpe;

import javax.persistence.*;
import java.util.List;

/**
 * This class represents a complex CPE object (CPE object attributes plus vulnerable etc. from CVE data feed JSON file)
 * <p>
 * It extends CPEobject class - adds a few attributes so that it can contain additional attributes gotten from CVE data feed JSON file
 * It can also store those additional attributes in the database including updates (Via CVEobject.putIntoDatabase() method)
 * <p>
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "compl_cpe")
public class CPEcomplexObj extends CPEobject {

    public CPEcomplexObj(){ } // default constructor

    protected Boolean vulnerable;
    protected String version_start_excluding;
    protected String version_end_excluding;
    protected String version_start_including;
    protected String version_end_including;

    @ManyToMany
    @CollectionTable(name = "cpe_compl_cpe", schema = "mitre")
    protected List<CPEobject> cpe;

    @OneToMany(mappedBy = "cpe")
    protected List<CPEnodeToComplex> node_to_compl;

    public List<CPEobject> getCpe_objs() {
        return cpe;
    }

    public void setCpe_objs(List<CPEobject> cpe) {
        this.cpe = cpe;
    }

    public List<CPEnodeToComplex> getNode_to_compl() {
        return node_to_compl;
    }

    public void setNode_to_compl(List<CPEnodeToComplex> node_to_compl) {
        this.node_to_compl = node_to_compl;
    }

    public Boolean getVulnerable() {
        return vulnerable;
    }

    public String getVersion_start_excluding() {
        return version_start_excluding;
    }

    public String getVersion_end_excluding() {
        return version_end_excluding;
    }

    public String getVersion_start_including() {
        return version_start_including;
    }

    public String getVersion_end_including() {
        return version_end_including;
    }

    /**
     * Copies constructor
     *
     * @param vulnerable              vulnerability boolean value for specific CPE object
     * @param version_start_excluding version start excluding parameter
     * @param version_end_excluding   version end excluding parameter
     * @param version_start_including version start including parameter
     * @param version_end_including   version end including parameter
     */
    public CPEcomplexObj(String cpe_id, String vendor, String product, String version, String update,
                         String edition, String language, String swEdition, String targetSw,
                         String targetHw, String other, Boolean vulnerable, String version_start_excluding,
                         String version_end_excluding, String version_start_including, String version_end_including) {
        super(cpe_id, vendor, product, version, update, edition, language, swEdition, targetSw, targetHw, other);

        this.vulnerable = vulnerable;
        this.version_start_excluding = version_start_excluding;
        this.version_start_including = version_start_including;
        this.version_end_excluding = version_end_excluding;
        this.version_end_including = version_end_including;
    }

    /**
     * This method's purpose is to create more complex CPE object from given parameters (with less complex
     * CPE object as first attribute) and return it
     *
     * @return more complex CPE object
     */
    public static CPEcomplexObj getInstanceFromCPE(CPEobject cpeUri, Boolean vulnerable, String version_start_excluding,
                                                   String version_end_excluding, String version_start_including, String version_end_including) {

        return new CPEcomplexObj(cpeUri.cpe_id, cpeUri.vendor, cpeUri.product, cpeUri.version, cpeUri.update, cpeUri.edition, cpeUri.language,
                cpeUri.swEdition, cpeUri.targetSw, cpeUri.targetHw, cpeUri.other, vulnerable, version_start_excluding,
                version_end_excluding, version_start_including, version_end_including);
    }

    ///**
    // * This method's purpose is to create more complex CPE object from given parameters and return it
    // *
    // * @return more complex CPE object
    // */
    //public static CPEcomplexObj getInstance(String cpe_id, String vendor, String product, String version, String update,
    //                                        String edition, String language, String swEdition, String targetSw,
    //                                        String targetHw, String other, Boolean vulnerable, String version_start_excluding,
    //                                        String version_end_excluding, String version_start_including, String version_end_including) {

    //    return new CPEcomplexObj(cpe_id, vendor, product, version, update, edition, language, swEdition, targetSw, targetHw, other, vulnerable,
    //            version_start_excluding, version_end_excluding, version_start_including, version_end_including);
    //}

    @Override
    public String toString() {
        return "CPEcomplexObj{" +
                "cpe_id='" + cpe_id + '\'' +
                ", vulnerable=" + vulnerable +
                ", version_start_excluding='" + version_start_excluding + '\'' +
                ", version_end_excluding='" + version_end_excluding + '\'' +
                ", version_start_including='" + version_start_including + '\'' +
                ", version_end_including='" + version_end_including + '\'' +
                ", vendor='" + vendor + '\'' +
                ", product='" + product + '\'' +
                ", version='" + version + '\'' +
                ", update='" + update + '\'' +
                ", edition='" + edition + '\'' +
                ", language='" + language + '\'' +
                ", swEdition='" + swEdition + '\'' +
                ", targetSw='" + targetSw + '\'' +
                ", targetHw='" + targetHw + '\'' +
                ", other='" + other + '\'' +
                '}';
    }
}
