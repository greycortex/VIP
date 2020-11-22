package mitre.capec;

import java.util.ArrayList;

/**
 * This class represents a CAPEC relation object (nature attribute, CAPEC code (ID) of related CAPEC attack pattern, exclude IDs)
 * <p>
 * //* It can create a CAPEC relation object from given parameters and return it
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CAPECrelationObj {

    protected String nature;
    protected String related_capec_id;
    protected ArrayList<String> exclude_ids;

    /**
     * Copies constructor
     *
     * @param nature            nature attribute
     * @param related_capec_id  CAPEC code (ID) of related CAPEC attack pattern
     * @param exclude_ids       exclude IDs
     */
    public CAPECrelationObj(String nature, String related_capec_id, ArrayList<String> exclude_ids) {

        this.nature = nature;
        this.related_capec_id = related_capec_id;
        this.exclude_ids = exclude_ids;

    }

    /**
     * This method's purpose is to create a CAPEC relation object from given parameters and return it
     *
     * @return CAPEC relation object
     */
    public static CAPECrelationObj getInstance(String nature, String related_capec_id, ArrayList<String> exclude_ids) {

        return new CAPECrelationObj(nature, related_capec_id, exclude_ids);
    }

    @Override
    public String toString() {
        return "CAPECrelationObj{" +
                "nature='" + nature + '\'' +
                ", related_capec_id='" + related_capec_id + '\'' +
                ", exclude_ids=" + exclude_ids +
                '}';
    }
}
