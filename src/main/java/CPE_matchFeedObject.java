
import com.google.gson.Gson;
import java.io.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class represents a CPE object (vendor, product, version, ...)
 *
 * It can read from file and insert it in the database including some updates.
 *
 * @author Tomas
 */
public class CPE_matchFeedObject implements Comparable {

    /**
     * DB Connection
     */
    private static Connection db;
    /**
     * Automatic ID
     */
    private final Long id;

    protected final String vendor;
    protected final String product;
    protected final String version;
    protected final String update;
    protected final String edition;
    protected final String language;
    protected final String swEdition;
    protected final String targetSw;
    protected final String targetHw;
    protected final String other;

    /**
     * Copy constructor
     *
     * @param vendor
     * @param product
     * @param version
     * @param update
     * @param edition
     * @param language
     * @param swEdition
     * @param targetSw
     * @param targetHw
     * @param other
     */
    public CPE_matchFeedObject(String vendor, String product, String version, String update, String edition, String language,
            String swEdition, String targetSw, String targetHw, String other) {

        this.id = null;
        this.vendor = vendor;
        this.product = product;
        this.version = version;
        this.update = update;
        this.edition = edition;
        this.language = language;
        this.swEdition = swEdition;
        this.targetSw = targetSw;
        this.targetHw = targetHw;
        this.other = other;
    }

    /**
     *
     * @return
     */
    public static ArrayList<String> parserToLineArrayList() {
        ArrayList<String> cpe23urilines = new ArrayList<>();
        ArrayList<CPE_matchFeedObject> obj_list = new ArrayList<CPE_matchFeedObject>();

        try (BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\Xarf\\Desktop\\VIP\\exclude\\nvdcpematch-1.0.json"))) {
            for (String line; (line = br.readLine()) != null;) {
                if (line.contains("cpe23Uri")) {
                    cpe23urilines.add(line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return cpe23urilines;
    }

    public static ArrayList<CPE_matchFeedObject> stringArrayListToObjectArraylist() throws FileNotFoundException {
        ArrayList<CPE_matchFeedObject> obj_list = new ArrayList<>();
        ArrayList<String> cpe23urilines = new ArrayList<>();
        cpe23urilines = parserToLineArrayList();

        for (String line : cpe23urilines) {

            String[] splitstr = line.split(":");

            for (int i = 0; i < splitstr.length; i++) {
                if (splitstr[i].equals("*") || splitstr[i].equals("*\",") || splitstr[i].equals("*\"")) {
                    splitstr[i] = null;
                }
                if (splitstr[i] != null) {
                    splitstr[i] = splitstr[i].replace("'", "''");
                    splitstr[i] = splitstr[i].replace("\\\\", "");
                    splitstr[i] = splitstr[i].replace("!", "");
                    /*Je obtizne najit specialni znaky, ktere by se daly nahradit, radeji to necham takto, aby
                                                                                   se pak nic neznicilo a mohlo se co nejlepe vyhledavat*/
                }
            }
            if (splitstr[13] != null) {
                splitstr[13] = splitstr[13].replace("\",", "");
                splitstr[13] = splitstr[13].replace("\"", "");
            }

            CPE_matchFeedObject obj = new CPE_matchFeedObject(splitstr[4], splitstr[5], splitstr[6], splitstr[7], splitstr[8], splitstr[9], splitstr[10], splitstr[11], splitstr[12], splitstr[13]);
            obj_list.add(obj);
        }
        return obj_list;
    }

    public static void obj_listToDatabase() throws ClassNotFoundException, SQLException, FileNotFoundException {
        ArrayList<CPE_matchFeedObject> obj_list = stringArrayListToObjectArraylist();
        ArrayList<String> url_conn = new ArrayList<>();

        try (BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\Xarf\\Desktop\\VIP\\exclude\\dbconnection.txt"))) { // "exclude\dbconnection.txt" -> umisteni souboru s connection url
            for (String line; (line = br.readLine()) != null;) {
                url_conn.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        Class.forName("org.postgresql.Driver");

        db = DriverManager.getConnection(url_conn.get(0));

        for (CPE_matchFeedObject object : obj_list) {
            Statement stat = db.createStatement();
            stat.execute("INSERT INTO cpe_match_feed_objects (vendor, product, version, update, edition, language, swedition, targetsw, targethw, other) "
                    + "VALUES ('" + object.vendor + "', '" + object.product + "', '" + object.version + "', '" + object.update + "', '" + object.edition + "', '" + object.language + "', '" + object.swEdition + "', "
                    + "'" + object.targetSw + "', '" + object.targetHw + "', '" + object.other + "')");
        }
        db.close();
    }

    /**
     *
     * @throws ClassNotFoundException
     * @throws SQLException
     * @throws NullPointerException
     * @throws FileNotFoundException
     */
    public static void comparingForUpdate() throws ClassNotFoundException, NullPointerException, FileNotFoundException {
        // list of objects from file (up-to-date)
        ArrayList<CPE_matchFeedObject> compared_objects = stringArrayListToObjectArraylist();
        // DB connection
        ArrayList<String> url_conn = new ArrayList<>();

        // read file ...
        try (BufferedReader br = new BufferedReader(new FileReader("exclude/dbconnection.txt"))) {
            for (String line; (line = br.readLine()) != null;) {
                url_conn.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // co to dela
        for (CPE_matchFeedObject obj : compared_objects) {
            try {
                // list of CPE objects with the same vendor (from DB)
                ArrayList<CPE_matchFeedObject> objects_to_compare = new ArrayList<>();

                // TODO: optimalizace
                // read the objects_to_compare (same vendor) from DB
                Class.forName("org.postgresql.Driver");
                db = DriverManager.getConnection(url_conn.get(0));
                Statement stat = db.createStatement();
                ResultSet result = stat.executeQuery("SELECT * FROM cpe_match_feed_objects WHERE vendor = '" + obj.vendor + "'");
                while (result.next()) {
                    CPE_matchFeedObject obj_to_compare = new CPE_matchFeedObject(result.getString(2), result.getString(3), result.getString(4), result.getString(5), result.getString(6),
                             result.getString(7), result.getString(8), result.getString(9), result.getString(10), result.getString(11));
                    objects_to_compare.add(obj_to_compare);
                }

                // whether is a duplicate object in DB
                int duplicity = 0;
                for (CPE_matchFeedObject compared_obj : objects_to_compare) { // ???
                    if (/* TODO + break */) ;

                    if (duplicity == 0) {
                        System.out.println("Jop");
                    }
                }

                // ... ???
                if (duplicity != 0) {
                    Statement addstat = db.createStatement();
                    addstat.execute("INSERT INTO cpe_match_feed_objects (vendor, product, version, update, edition, language, swedition, targetsw, targethw, other) "
                            + "VALUES ('" + obj.vendor + "', '" + obj.product + "', '" + obj.version + "', '" + obj.update + "', '" + obj.edition + "', '" + obj.language + "', '" + obj.swEdition + "', "
                            + "'" + obj.targetSw + "', '" + obj.targetHw + "', '" + obj.other + "')");

                }
            } catch (SQLException ex) {
                Logger.getLogger(CPE_matchFeedObject.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                try {
                    db.close();
                } catch (SQLException ex) {
                    Logger.getLogger(CPE_matchFeedObject.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    @Override
    public String toString() {
        return "CPE_matchFeedObject{"
                + "vendor='" + vendor + '\''
                + ", product='" + product + '\''
                + ", version='" + version + '\''
                + ", update='" + update + '\''
                + ", edition='" + edition + '\''
                + ", language='" + language + '\''
                + ", swEdition='" + swEdition + '\''
                + ", targetSw='" + targetSw + '\''
                + ", targetHw='" + targetHw + '\''
                + ", other='" + other + '\''
                + '}';
    }

    /**
     * Compares to other
     *
     * @param other
     * @return
     */
    @Override
    public int compareTo(Object other) {
        if (other.getClass().getName().compareTo(this.getClass().getName()) != 0) {
            return Integer.MIN_VALUE;
        }
        return this.compareTo((CPE_matchFeedObject) other);
    }

    public int compareTo(CPE_matchFeedObject other) {
        // id does not need to be compared
        if (this.vendor == null && other.vendor == null) ; // cajk
        else if (this.vendor != null && other.vendor == null) {
            return -1; // TODO: check
        } else if (this.vendor == null && other.vendor != null) {
            return 1;
        } else if (this.vendor.compareToIgnoreCase(other.vendor) != 0) {
            return this.vendor.compareToIgnoreCase(other.vendor);
        }

        if (this.product.compareToIgnoreCase(other.product) != 0) {
            return this.product.compareToIgnoreCase(other.product);
        }

        // ...
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates. - TODO: delete this line.

    }
}
