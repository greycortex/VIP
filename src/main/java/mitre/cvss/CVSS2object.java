package mitre.cvss;

/**
 * This class represents a CVSS v2 object (Base score metrics, ...)
 * <p>
 * //* It can create a CVSS v2 (base metric v2) object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CVSS2object {

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

    /**
     * This method's purpose is to create a CVSS v2 (base metric v2) object from given parameters and return it
     *
     * @return CVSS v2 (base metric v2) object
     */
    public static CVSS2object getInstance(String version, String vector_string, String access_vector, String access_complexity,
                                          String authentication, String confidentiality_impact, String integrity_impact,
                                          String availability_impact, double base_score_v2, String severity,
                                          double exploitability_score_v2, double impact_score_v2, String ac_insuf_info,
                                          String obtain_all_privilege, String obtain_user_privilege, String obtain_other_privilege,
                                          String user_interaction_required) {

        return new CVSS2object(version, vector_string, access_vector, access_complexity, authentication, confidentiality_impact,
                integrity_impact, availability_impact, base_score_v2, severity, exploitability_score_v2, impact_score_v2, ac_insuf_info,
                obtain_all_privilege, obtain_user_privilege, obtain_other_privilege, user_interaction_required);
    }

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
}
