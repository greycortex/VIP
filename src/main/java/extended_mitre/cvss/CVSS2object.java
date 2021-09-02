package extended_mitre.cvss;

import extended_mitre.cve.CVEobject;

import javax.persistence.*;
import java.util.Objects;

/**
 * This class represents a CVSS v2 object (Base score metrics, ...)
 * <p>
 * It can create a CVSS v2 (base metric v2) object from given parameters and return it
 * Objects can be put into database including quick updates
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "cvss2")
@Table(name="cvss2", schema = "mitre")
public class CVSS2object {

    public CVSS2object() { } // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    protected String version;
    protected String vector_string;
    protected String access_vector;
    protected String access_complexity;
    protected String authentication;
    protected String confidentiality_impact;
    protected String integrity_impact;
    protected String availability_impact;
    protected double base_score_v2;
    protected String severity;
    protected double exploitability_score_v2;
    protected double impact_score_v2;
    protected String ac_insuf_info;
    protected String obtain_all_privilege;
    protected String obtain_user_privilege;
    protected String obtain_other_privilege;
    protected String user_interaction_required;
    @OneToOne(mappedBy = "cvss_v2")
    protected CVEobject cve_obj;

    /**
     * Copies constructor
     *
     * @param version                   CVSS v2 version
     * @param vector_string             vector string
     * @param access_vector             access vector attribute
     * @param access_complexity         access complexity attribute
     * @param authentication            authentication attribute
     * @param confidentiality_impact    confidentiality impact attribute
     * @param integrity_impact          integrity impact attribute
     * @param availability_impact       availability impact attribute
     * @param base_score_v2             base score given by CVSS v2 calculator
     * @param severity                  severity attribute
     * @param exploitability_score_v2   exploitability subscore given by CVSS v2 calculator
     * @param impact_score_v2           impact subscore given by CVSS v2 calculator
     * @param ac_insuf_info             ac. insufficient info boolean attribute
     * @param obtain_all_privilege      obtain all privilege boolean attribute
     * @param obtain_user_privilege     obtain user privilege boolean attribute
     * @param obtain_other_privilege    obtain other privilege boolean attribute
     * @param user_interaction_required user interaction required boolean attribute
     */
    public CVSS2object(String version, String vector_string, String access_vector, String access_complexity,
                       String authentication, String confidentiality_impact, String integrity_impact,
                       String availability_impact, double base_score_v2, String severity, double exploitability_score_v2,
                       double impact_score_v2, String ac_insuf_info, String obtain_all_privilege, String obtain_user_privilege,
                       String obtain_other_privilege, String user_interaction_required) {

        this.version = version;
        this.vector_string = vector_string;
        this.access_vector = access_vector;
        this.access_complexity = access_complexity;
        this.authentication = authentication;
        this.confidentiality_impact = confidentiality_impact;
        this.integrity_impact = integrity_impact;
        this.availability_impact = availability_impact;
        this.base_score_v2 = base_score_v2;
        this.severity = severity;
        this.exploitability_score_v2 = exploitability_score_v2;
        this.impact_score_v2 = impact_score_v2;
        this.ac_insuf_info = ac_insuf_info;
        this.obtain_all_privilege = obtain_all_privilege;
        this.obtain_user_privilege = obtain_user_privilege;
        this.obtain_other_privilege = obtain_other_privilege;
        this.user_interaction_required = user_interaction_required;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getVector_string() {
        return vector_string;
    }

    public void setVector_string(String vector_string) {
        this.vector_string = vector_string;
    }

    public String getAccess_vector() {
        return access_vector;
    }

    public void setAccess_vector(String access_vector) {
        this.access_vector = access_vector;
    }

    public String getAccess_complexity() {
        return access_complexity;
    }

    public void setAccess_complexity(String access_complexity) {
        this.access_complexity = access_complexity;
    }

    public String getAuthentication() {
        return authentication;
    }

    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    public String getConfidentiality_impact() {
        return confidentiality_impact;
    }

    public void setConfidentiality_impact(String confidentiality_impact) {
        this.confidentiality_impact = confidentiality_impact;
    }

    public String getIntegrity_impact() {
        return integrity_impact;
    }

    public void setIntegrity_impact(String integrity_impact) {
        this.integrity_impact = integrity_impact;
    }

    public String getAvailability_impact() {
        return availability_impact;
    }

    public void setAvailability_impact(String availability_impact) {
        this.availability_impact = availability_impact;
    }

    public double getBase_score_v2() {
        return base_score_v2;
    }

    public void setBase_score_v2(double base_score_v2) {
        this.base_score_v2 = base_score_v2;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public double getExploitability_score_v2() {
        return exploitability_score_v2;
    }

    public void setExploitability_score_v2(double exploitability_score_v2) {
        this.exploitability_score_v2 = exploitability_score_v2;
    }

    public double getImpact_score_v2() {
        return impact_score_v2;
    }

    public void setImpact_score_v2(double impact_score_v2) {
        this.impact_score_v2 = impact_score_v2;
    }

    public String getAc_insuf_info() {
        return ac_insuf_info;
    }

    public void setAc_insuf_info(String ac_insuf_info) {
        this.ac_insuf_info = ac_insuf_info;
    }

    public String getObtain_all_privilege() {
        return obtain_all_privilege;
    }

    public void setObtain_all_privilege(String obtain_all_privilege) {
        this.obtain_all_privilege = obtain_all_privilege;
    }

    public String getObtain_user_privilege() {
        return obtain_user_privilege;
    }

    public void setObtain_user_privilege(String obtain_user_privilege) {
        this.obtain_user_privilege = obtain_user_privilege;
    }

    public String getObtain_other_privilege() {
        return obtain_other_privilege;
    }

    public void setObtain_other_privilege(String obtain_other_privilege) {
        this.obtain_other_privilege = obtain_other_privilege;
    }

    public String getUser_interaction_required() {
        return user_interaction_required;
    }

    public void setUser_interaction_required(String user_interaction_required) {
        this.user_interaction_required = user_interaction_required;
    }

    ///**
    // * This method's purpose is to create a CVSS v2 (base metric v2) object from given parameters and return it
    // *
    // * @return CVSS v2 (base metric v2) object
    // */
    //public static CVSS2object getInstance(String version, String vector_string, String access_vector, String access_complexity,
    //                                      String authentication, String confidentiality_impact, String integrity_impact,
    //                                      String availability_impact, double base_score_v2, String severity,
    //                                      double exploitability_score_v2, double impact_score_v2, String ac_insuf_info,
    //                                      String obtain_all_privilege, String obtain_user_privilege, String obtain_other_privilege,
    //                                      String user_interaction_required) {

    //    return new CVSS2object(version, vector_string, access_vector, access_complexity, authentication, confidentiality_impact,
    //            integrity_impact, availability_impact, base_score_v2, severity, exploitability_score_v2, impact_score_v2, ac_insuf_info,
    //            obtain_all_privilege, obtain_user_privilege, obtain_other_privilege, user_interaction_required);
    //}

    @Override
    public String toString() {
        return "CVSS2object{" +
                "version='" + version + '\'' +
                ", vector_string='" + vector_string + '\'' +
                ", access_vector='" + access_vector + '\'' +
                ", access_complexity='" + access_complexity + '\'' +
                ", authentication='" + authentication + '\'' +
                ", confidentiality_impact='" + confidentiality_impact + '\'' +
                ", integrity_impact='" + integrity_impact + '\'' +
                ", availability_impact='" + availability_impact + '\'' +
                ", base_score_v2='" + base_score_v2 + '\'' +
                ", severity='" + severity + '\'' +
                ", exploitability_score_v2='" + exploitability_score_v2 + '\'' +
                ", impact_score_v2='" + impact_score_v2 + '\'' +
                ", ac_insuf_info=" + ac_insuf_info +
                ", obtain_all_privilege=" + obtain_all_privilege +
                ", obtain_user_privilege=" + obtain_user_privilege +
                ", obtain_other_privilege=" + obtain_other_privilege +
                ", user_interaction_required=" + user_interaction_required +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CVSS2object)) return false;
        CVSS2object that = (CVSS2object) o;
        return Double.compare(that.base_score_v2, base_score_v2) == 0 && Double.compare(that.exploitability_score_v2, exploitability_score_v2) == 0 && Double.compare(that.impact_score_v2, impact_score_v2) == 0 && Objects.equals(version, that.version) && Objects.equals(vector_string, that.vector_string) && Objects.equals(access_vector, that.access_vector) && Objects.equals(access_complexity, that.access_complexity) && Objects.equals(authentication, that.authentication) && Objects.equals(confidentiality_impact, that.confidentiality_impact) && Objects.equals(integrity_impact, that.integrity_impact) && Objects.equals(availability_impact, that.availability_impact) && Objects.equals(severity, that.severity) && Objects.equals(ac_insuf_info, that.ac_insuf_info) && Objects.equals(obtain_all_privilege, that.obtain_all_privilege) && Objects.equals(obtain_user_privilege, that.obtain_user_privilege) && Objects.equals(obtain_other_privilege, that.obtain_other_privilege) && Objects.equals(user_interaction_required, that.user_interaction_required);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, vector_string, access_vector, access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, base_score_v2, severity, exploitability_score_v2, impact_score_v2, ac_insuf_info, obtain_all_privilege, obtain_user_privilege, obtain_other_privilege, user_interaction_required);
    }
}
