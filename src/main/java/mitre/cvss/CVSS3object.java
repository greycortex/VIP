package mitre.cvss;

import mitre.cve.CVEobject;

import javax.persistence.*;

/**
 * This class represents a CVSS v3 object (Base score metrics, ...)
 * <p>
 * //* It can create a CVSS v3 (base metric v3) object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity
@Table(name="cvss3object")
public class CVSS3object {

    public CVSS3object() { } // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    protected Long id;
    protected String version;
    protected String vector_string;
    protected String attack_vector;
    protected String attack_complexity;
    protected String privileges_required;
    protected String user_interaction;
    protected String scope;
    protected String confidentiality_impact;
    protected String integrity_impact;
    protected String availability_impact;
    protected double base_score_v3;
    protected String base_severity_v3;
    protected double exploitability_score_v3;
    protected double impact_score_v3;
    @OneToOne(mappedBy = "cvss_v3")
    protected CVEobject cve_obj;

    /**
     * Copies constructor
     *
     * @param version                 CVSS v3 version
     * @param vector_string           vector string
     * @param attack_vector           attack vector attribute
     * @param attack_complexity       attack complexity attribute
     * @param privileges_required     privileges required attribute
     * @param user_interaction        user interaction attribute
     * @param scope                   scope attribute
     * @param confidentiality_impact  confidentiality impact attribute
     * @param integrity_impact        integrity impact attribute
     * @param availability_impact     availability impact attribute
     * @param base_score_v3           base score given by CVSS v3 calculator
     * @param base_severity_v3        base severity
     * @param exploitability_score_v3 exploitability subscore given by CVSS v3 calculator
     * @param impact_score_v3         impact subscore given by CVSS v3 calculator
     */
    public CVSS3object(String version, String vector_string, String attack_vector, String attack_complexity,
                       String privileges_required, String user_interaction, String scope, String confidentiality_impact,
                       String integrity_impact, String availability_impact, double base_score_v3, String base_severity_v3,
                       double exploitability_score_v3, double impact_score_v3) {

        this.version = version;
        this.vector_string = vector_string;
        this.attack_vector = attack_vector;
        this.attack_complexity = attack_complexity;
        this.privileges_required = privileges_required;
        this.user_interaction = user_interaction;
        this.scope = scope;
        this.confidentiality_impact = confidentiality_impact;
        this.integrity_impact = integrity_impact;
        this.availability_impact = availability_impact;
        this.base_score_v3 = base_score_v3;
        this.base_severity_v3 = base_severity_v3;
        this.exploitability_score_v3 = exploitability_score_v3;
        this.impact_score_v3 = impact_score_v3;
    }

    ///**
    // * This method's purpose is to create a CVSS v3 (base metric v3) object from given parameters and return it
    // *
    // * @return CVSS v3 (base metric v3) object
    // */
    //public static CVSS3object getInstance(String version, String vector_string, String attack_vector, String attack_complexity, String privileges_required,
    //                                      String user_interaction, String scope, String confidentiality_impact, String integrity_impact,
    //                                      String availability_impact, double base_score_v3, String base_severity_v3, double exploitability_score_v3,
    //                                      double impact_score_v3) {

    //    return new CVSS3object(version, vector_string, attack_vector, attack_complexity, privileges_required, user_interaction, scope,
    //            confidentiality_impact, integrity_impact, availability_impact, base_score_v3, base_severity_v3, exploitability_score_v3,
    //            impact_score_v3);
    //}

    @Override
    public String toString() {
        return "CVSS3object{" +
                "version='" + version + '\'' +
                ", vector_string='" + vector_string + '\'' +
                ", attack_vector='" + attack_vector + '\'' +
                ", attack_complexity='" + attack_complexity + '\'' +
                ", privileges_required='" + privileges_required + '\'' +
                ", user_interaction='" + user_interaction + '\'' +
                ", scope='" + scope + '\'' +
                ", confidentiality_impact='" + confidentiality_impact + '\'' +
                ", integrity_impact='" + integrity_impact + '\'' +
                ", availability_impact='" + availability_impact + '\'' +
                ", base_score_v3='" + base_score_v3 + '\'' +
                ", base_severity_v3='" + base_severity_v3 + '\'' +
                ", exploitability_score_v3='" + exploitability_score_v3 + '\'' +
                ", impact_score_v3='" + impact_score_v3 + '\'' +
                '}';
    }
}
