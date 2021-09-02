package extended_mitre.cpe;

import javax.persistence.*;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a complex CPE object (basic CPE object attributes plus vulnerable etc. from CVE data feed JSON file)
 * <p>
 * It extends CPEobject class - adds a few attributes so that it can contain additional attributes gotten from CVE data feed JSON file
 * Objects can be put into database including quick updates
 * <p>
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "compl_cpe_ex")
@Table(name = "compl_cpe", schema = "mitre", indexes = @Index(name = "compl_cpe_vendor_product_idx", columnList = "vendor, product"))
public class CPEcomplexObj extends CPEobject implements Serializable {

    public CPEcomplexObj(){ } // default constructor

    protected Boolean vulnerable;
    protected String version_start_excluding;
    protected String version_end_excluding;
    protected String version_start_including;
    protected String version_end_including;

    @ManyToMany
    @CollectionTable(name = "cpe_compl_cpe", schema = "mitre")
    protected List<CPEobject> cpe;

    @OneToMany(mappedBy = "compl_cpe")
    protected List<CPEnodeToCPE> node_to_compl;

    public List<CPEobject> getCpe_objs() {
        return cpe;
    }

    public void setCpe_objs(List<CPEobject> cpe) {
        this.cpe = cpe;
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
     * @param cpe_id                  CPE ID - cpeUri String
     * @param vendor                  vendor attribute
     * @param product                 product attribute
     * @param version                 version attribute
     * @param update                  update attribute
     * @param edition                 edition attribute
     * @param language                language attribute
     * @param swEdition               software edition attribute
     * @param targetSw                target software attribute
     * @param targetHw                target hardware attribute
     * @param other                   other attribute
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
     * This method's purpose is to create more complex CPE object from given parameters (with basic
     * CPE object as first attribute) and return it
     *
     * @param cpeUri                  cpeUri String - contains basic CPE attributes
     * @param vulnerable              vulnerability boolean value for specific CPE object
     * @param version_start_excluding version start excluding parameter
     * @param version_end_excluding   version end excluding parameter
     * @param version_start_including version start including parameter
     * @param version_end_including   version end including parameter
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CPEcomplexObj)) return false;
        if (!super.equals(o)) return false;
        CPEcomplexObj that = (CPEcomplexObj) o;
        return Objects.equals(vulnerable, that.vulnerable) && Objects.equals(version_start_excluding, that.version_start_excluding) && Objects.equals(version_end_excluding, that.version_end_excluding) && Objects.equals(version_start_including, that.version_start_including) && Objects.equals(version_end_including, that.version_end_including);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), vulnerable, version_start_excluding, version_end_excluding, version_start_including, version_end_including);
    }
}
