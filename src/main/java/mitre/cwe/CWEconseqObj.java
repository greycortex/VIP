package mitre.cwe;

import mitre.capec.CAPECobject;

import javax.persistence.*;
import java.util.List;
import java.util.Objects;

/**
 * This class represents a CWE consequence object (scope attributes, impact attributes, note attributes, likelihood attributes)
 * <p>
 * Objects can be put into database including updates (Via CVEobject.putIntoDatabase() method)
 * <p>
 * //* It can create a CWE consequence object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
@Entity(name = "consequence")
@Table(name="consequence", schema = "mitre")
public class CWEconseqObj {

    public CWEconseqObj() {} // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;
    @Column(name = "scope")
    @CollectionTable(name = "conseq_scopes", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> scopes;
    @Column(name = "impact")
    @CollectionTable(name = "conseq_impacts", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> impacts;
    @Column(name = "note", length = 8191)
    @CollectionTable(name = "conseq_notes", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> notes;
    @Column(name = "likelihood")
    @CollectionTable(name = "conseq_likelihoods", schema = "mitre")
    @ElementCollection(targetClass = String.class)
    protected List<String> likelihoods;
    @ManyToOne
    protected CAPECobject capec;
    @ManyToOne
    protected CWEobject cwe;

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

    public void setCwe(CWEobject cwe) {
        this.cwe = cwe;
    }

    public void setCapec(CAPECobject capec) {
        this.capec = capec;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CWEconseqObj)) return false;
        CWEconseqObj that = (CWEconseqObj) o;
        return Objects.equals(id, that.id) && Objects.equals(scopes, that.scopes) && Objects.equals(impacts, that.impacts) && Objects.equals(notes, that.notes) && Objects.equals(likelihoods, that.likelihoods) && Objects.equals(capec, that.capec) && Objects.equals(cwe, that.cwe);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, scopes, impacts, notes, likelihoods, capec, cwe);
    }
}
