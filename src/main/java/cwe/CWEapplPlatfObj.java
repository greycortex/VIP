package cwe;

/**
 * This class represents a CWE application platform object (type attribute, class attribute, name attribute, prevalence attribute)
 * <p>
 * //* It can create a CWE application platform object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEapplPlatfObj {

    protected String type;
    protected String platform_class;
    protected String name;
    protected String prevalence;

    /**
     * Copies constructor
     *
     * @param type           type attribute
     * @param platform_class platform_class attribute
     * @param name           name attribute
     * @param prevalence     prevalence attribute
     */
    public CWEapplPlatfObj(String type, String platform_class, String name, String prevalence) {

        this.type = type;
        this.platform_class = platform_class;
        this.name = name;
        this.prevalence = prevalence;

    }

    /**
     * This method's purpose is to create a CWE application platform object from given parameters and return it
     *
     * @return CWE application platform object
     */
    public static CWEapplPlatfObj getInstance(String type, String platform_class, String name, String prevalence) {

        return new CWEapplPlatfObj(type, platform_class, name, prevalence);
    }

    @Override
    public String toString() {
        return "CWEapplPlatfObj{" +
                "type='" + type + '\'' +
                ", platform_class='" + platform_class + '\'' +
                ", name='" + name + '\'' +
                ", prevalence='" + prevalence + '\'' +
                '}';
    }
}
