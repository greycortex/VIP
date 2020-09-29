/**
 * This class represents a CWE demonstrative example - example code object (nature attribute, language attribute, content)
 * <p>
 * //* It can create a CWE demonstrative example - example code object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEexampCodeObj {

    protected String nature;
    protected String language;
    protected String content;

    /**
     * Copies constructor
     *
     * @param nature   nature attribute
     * @param language language attributes
     * @param content  content
     */
    public CWEexampCodeObj(String nature, String language, String content) {

        this.nature = nature;
        this.language = language;
        this.content = content;

    }

    /**
     * This method's purpose is to create a CWE demonstrative example - example code object from given parameters and return it
     *
     * @return CWE demonstrative example - example code object
     */
    public static CWEexampCodeObj getInstance(String nature, String language, String content) {

        return new CWEexampCodeObj(nature, language, content);
    }

    @Override
    public String toString() {
        return "CWEexampCodeObj{" +
                "nature='" + nature + '\'' +
                ", language='" + language + '\'' +
                ", language='" + content + '\'' +
                '}';
    }
}
