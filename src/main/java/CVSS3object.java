
/**
 * This class represents a CVSS v3 object (Base score metrics, ...)
 *
 * --- Description of the class ---
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CVSS3object {

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
    protected String base_score_v3;
    protected String base_severity_v3;
    protected String exploitability_score_v3;
    protected String impact_score_v3;

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
                       String integrity_impact, String availability_impact, String base_score_v3, String base_severity_v3,
                       String exploitability_score_v3, String impact_score_v3) {

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

}
