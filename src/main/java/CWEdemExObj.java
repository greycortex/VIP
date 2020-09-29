import java.util.ArrayList;

/**
 * This class represents a CWE demonstrative example object (nature attribute, language attribute, content)
 * <p>
 * //* It can create a CWE demonstrative example object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CWEdemExObj {

    protected String intro_text;
    protected ArrayList<CWEexampCodeObj> dem_ex_ex_codes;
    protected ArrayList<String> dem_ex_body_texts;
    protected ArrayList<CWEextRefRefObj> dem_ex_ext_ref_refs;

    /**
     * Copies constructor
     *
     * @param intro_text          intro text attribute
     * @param dem_ex_ex_codes     example code objects
     * @param dem_ex_body_texts   body text attributes
     * @param dem_ex_ext_ref_refs external reference reference objects
     */
    public CWEdemExObj(String intro_text, ArrayList<CWEexampCodeObj> dem_ex_ex_codes, ArrayList<String> dem_ex_body_texts,
                       ArrayList<CWEextRefRefObj> dem_ex_ext_ref_refs) {

        this.intro_text = intro_text;
        this.dem_ex_ex_codes = dem_ex_ex_codes;
        this.dem_ex_body_texts = dem_ex_body_texts;
        this.dem_ex_ext_ref_refs = dem_ex_ext_ref_refs;

    }

    /**
     * This method's purpose is to create a CWE demonstrative example object from given parameters and return it
     *
     * @return CWE demonstrative example object
     */
    public static CWEdemExObj getInstance(String intro_text, ArrayList<CWEexampCodeObj> dem_ex_ex_codes, ArrayList<String> dem_ex_body_texts,
                                          ArrayList<CWEextRefRefObj> dem_ex_ext_ref_refs) {

        return new CWEdemExObj(intro_text, dem_ex_ex_codes, dem_ex_body_texts, dem_ex_ext_ref_refs);
    }

    @Override
    public String toString() {
        return "CWEdemExObj{" +
                "intro_text='" + intro_text + '\'' +
                ", dem_ex_ex_codes=" + dem_ex_ex_codes +
                ", dem_ex_body_texts=" + dem_ex_body_texts +
                ", dem_ex_ext_ref_refs=" + dem_ex_ext_ref_refs +
                '}';
    }
}
