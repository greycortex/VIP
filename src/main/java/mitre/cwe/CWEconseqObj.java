package mitre.cwe;

import java.util.ArrayList;

/**
 * This class represents a CWE consequence object (scope attributes, impact attributes, note attributes, likelihood attributes)
 * <p>
 * //* It can create a CWE consequence object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEconseqObj {

    protected ArrayList<String> scopes;
    protected ArrayList<String> impacts;
    protected ArrayList<String> notes;
    protected ArrayList<String> likelihoods;

    /**
     * Copies constructor
     *
     * @param scopes      scope
     * @param impacts     impact attributes
     * @param notes       note attributes
     * @param likelihoods likelihood attributes
     */
    public CWEconseqObj(ArrayList<String> scopes, ArrayList<String> impacts, ArrayList<String> notes,
                        ArrayList<String> likelihoods) {

        this.scopes = scopes;
        this.impacts = impacts;
        this.notes = notes;
        this.likelihoods = likelihoods;

    }

    /**
     * This method's purpose is to create a CWE consequence object from given parameters and return it
     *
     * @return CWE consequence object
     */
    public static CWEconseqObj getInstance(ArrayList<String> scopes, ArrayList<String> impacts, ArrayList<String> notes,
                                           ArrayList<String> likelihoods) {

        return new CWEconseqObj(scopes, impacts, notes, likelihoods);
    }

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
