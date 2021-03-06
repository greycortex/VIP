package mitre.capec;

/**
 * This class represents a CAPEC skill object (level attribute, skill info)
 * <p>
 * //* It can create a CAPEC skill object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CAPECskillObj {

    protected String level;
    protected String content;

    /**
     * Copies constructor
     *
     * @param level         level attribute
     * @param content       skill info
     */
    public CAPECskillObj(String level, String content){

        this.level = level;
        this.content = content;

    }

    ///**
    // * This method's purpose is to create a CAPEC skill object from given parameters and return it
    // *
    // * @return CAPEC skill object
    // */
    //public static CAPECskillObj getInstance(String level, String content) {

    //    return new CAPECskillObj(level, content);
    //}

    @Override
    public String toString() {
        return "CAPECskillObj{" +
                "level='" + level + '\'' +
                ", content='" + content + '\'' +
                '}';
    }
}
