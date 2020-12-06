package mitre.cwe;

import java.util.List;

/**
 * This class represents a CWE consequence object (scope attributes, impact attributes, note attributes, likelihood attributes)
 * <p>
 * //* It can create a CWE consequence object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEconseqObj {

    protected List<String> scopes;
    protected List<String> impacts;
    protected List<String> notes;
    protected List<String> likelihoods;

    /**
     * Copies constructor
     *
     * @param scopes      scope
     * @param impacts     impact attributes
     * @param notes       note attributes
     * @param likelihoods likelihood attributes
     */
    public CWEconseqObj(List<String> scopes, List<String> impacts, List<String> notes,
                        List<String> likelihoods) {

        this.scopes = scopes;
        this.impacts = impacts;
        this.notes = notes;
        this.likelihoods = likelihoods;

    }

    ///**
    // * This method's purpose is to create a CWE consequence object from given parameters and return it
    // *
    // * @return CWE consequence object
    // */
    //public static CWEconseqObj getInstance(List<String> scopes, List<String> impacts, List<String> notes,
    //                                       List<String> likelihoods) {

    //    return new CWEconseqObj(scopes, impacts, notes, likelihoods);
    //}

    @Override
    public String toString() {
        return "CWEconseqObj{" +
                "scopes=" + scopes +
                ", impacts=" + impacts +
                ", notes=" + notes +
                ", likelihoods=" + likelihoods +
                '}';
    }
}
