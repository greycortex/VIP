package cwe;

/**
 * This class represents a CWE alternate term object (term attribute, description attribute)
 * <p>
 * //* It can create a CWE alternate term object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEalterTermObj {

    protected String term;
    protected String description;

    /**
     * Copies constructor
     *
     * @param term        term attribute
     * @param description description attribute
     */
    public CWEalterTermObj(String term, String description) {

        this.term = term;
        this.description = description;

    }

    /**
     * This method's purpose is to create a CWE alternate term object from given parameters and return it
     *
     * @return CWE alternate term object
     */
    public static CWEalterTermObj getInstance(String term, String description) {

        return new CWEalterTermObj(term, description);
    }

    @Override
    public String toString() {
        return "CWEalterTermObj{" +
                "term='" + term + '\'' +
                ", description='" + description + '\'' +
                '}';
    }
}
