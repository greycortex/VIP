package mitre.cve;

import java.util.List;

/**
 * This class represents a reference object which can be found in CVE object
 * <p>
 * //* Its purpose is to create reference objects which are then put into CVE objects
 *
 * @author Tomas Bozek (XarfNao)
 */
public class ReferenceObject {

    protected String url;
    protected String name;
    protected String refsource;
    protected List<String> tags;

    /**
     * Copies constructor
     *
     * @param url       reference url
     * @param name      name of the reference
     * @param refsource refsource attribute
     * @param tags      tags of the reference
     */
    public ReferenceObject(String url, String name, String refsource, List<String> tags) {

        this.url = url;
        this.name = name;
        this.refsource = refsource;
        this.tags = tags;
    }

    ///**
    // * This method's purpose is to create a reference object from given parameters and return it
    // *
    // * @return reference object
    // */
    //public static ReferenceObject getInstance(String url, String name, String refsource, List<String> tags) {

    //    return new ReferenceObject(url, name, refsource, tags);
    //}

    @Override
    public String toString() {
        return "ReferenceObject{" +
                "url='" + url + '\'' +
                ", name='" + name + '\'' +
                ", refsource='" + refsource + '\'' +
                ", tags=" + tags +
                '}';
    }
}
