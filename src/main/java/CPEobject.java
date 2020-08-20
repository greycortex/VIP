import java.io.*;
import java.sql.*;
import java.util.ArrayList;

/**
 * This class represents a CPE object (vendor, product, version, ...)
 *
 * It can read from file, create objects representing vulnerabilities and insert them into the database including updates
 *
 * @author Tomas Bozek (XarfNao)
 */
public class CPEobject {

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
     * Copies constructor
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
    public CPEobject(String vendor, String product, String version, String update, String edition, String language,
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
     * @return ArrayList that contains parsed lines (Strings) from the CPE file
     * @throws IOException
     */
    public static ArrayList<String> parserToLineArrayList() {

        // ArrayList which will contain parsed lines from the CPE file
        ArrayList<String> cpe23urilines = new ArrayList<>();

        // This block of code goes through the selected file line by line and add the lines that contain "cpe23uri" to the cpe23urilines ArrayList
        try (BufferedReader br = new BufferedReader(new FileReader("exclude/nvdcpematch-1.0.json"))) {
            for (String line; (line = br.readLine()) != null; ) {
                if (line.contains("cpe23Uri")) {
                    cpe23urilines.add(line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return cpe23urilines;
    }

    /**
     * @return ArrayList that contains CPE objects made from the cpe23urilines ArrayList returned by the parserToLineArrayList() method
     */
    public static ArrayList<CPEobject> stringArrayListToObjectArraylist() {

        // Defining the object ArrayList
        ArrayList<CPEobject> obj_list = new ArrayList<>();

        // Taking the lines returned by the parserToLineArrayList() method
        ArrayList<String> cpe23urilines = new ArrayList<>();
        cpe23urilines = parserToLineArrayList();

        // We go line by line (object by object)
        for (String line : cpe23urilines) {

            // This array is filled with parts of the line (separates by ":")
            String[] splitstr = line.split(":");

            /**
             * This for cycle goes through each part of the splitstr array and changes its parts so that they are
             * more database and search friendly and have a better form in general
             */
            for (int i = 0; i < splitstr.length; i++) {

                // This replaces all the "*" characters (which mean an empty parameter)
                if (splitstr[i].equals("*") || splitstr[i].equals("*\",") || splitstr[i].equals("*\"")) {
                    splitstr[i] = null;
                }

                /**
                 * This block of code replaces all the sql-not-frinedly apostrophes with a sql-friendly apostrophes,
                 * it also removes backslashes and exclamation marks in a weird places
                 */
                if (splitstr[i] != null) {
                    splitstr[i] = splitstr[i].replace("'", "''");
                    splitstr[i] = splitstr[i].replace("\\\\", "");
                    splitstr[i] = splitstr[i].replace("!", "");
                }
            }

            //This block of code removes the apostrophes that can appear at the end of the line
            if (splitstr[13] != null) {
                splitstr[13] = splitstr[13].replace("\",", "");
                splitstr[13] = splitstr[13].replace("\"", "");
            }

            // Finally creates a new CPE object using changed parts of the splitstr array
            CPEobject obj = new CPEobject(splitstr[4], splitstr[5], splitstr[6], splitstr[7], splitstr[8], splitstr[9], splitstr[10], splitstr[11], splitstr[12], splitstr[13]);
            obj_list.add(obj);
        }

        return obj_list;
    }

    /**
     * This method puts all the created objects from the stringArrayListToObjectArraylist() method into a local database
     *
     * @throws ClassNotFoundException
     * @throws SQLException
     * @throws IOException
     */
    public static void objListToDatabase() {

        // Arraylist of objects returned by the stringArrayListToObjectArraylist() method
        ArrayList<CPEobject> obj_list = stringArrayListToObjectArraylist();

        // This ArrayList of strings contains only one string from a separate file which contains a connection url (a name and a password included)
        ArrayList<String> url_conn = new ArrayList<>();

        /**
         * "exclude\dbconnection.txt" -> place of the separate file with the connection url
         * This block of code takes the connection url from the separate file and puts it into the url_conn's 0 index
         */
        try (BufferedReader br = new BufferedReader(new FileReader("exclude/dbconnection.txt"))) {
            for (String line; (line = br.readLine()) != null; ) {
                url_conn.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }


        try {
            Class.forName("org.postgresql.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        // This block of code uses the connection url from the url_conn's 0 index and connects to the database

        try {

            // Connection to the database
            db = DriverManager.getConnection(url_conn.get(0));

            /**
             * This for cycle goes through the object ArrayList full of CPE objects object by object and puts them into the database
             * null values handling included
             */
            for (CPEobject object : obj_list) {
                PreparedStatement stat = db.prepareStatement("INSERT INTO cpe_match_feed_objects (vendor, product, version, update, edition, language, swedition, targetsw, targethw, other) "
                        + "VALUES ('"+object.vendor+"','"+object.product+"',?,?,?,?,?,?,?,?)");
                if(object.version == null) stat.setString(1,null);
                else stat.setString(1, object.version);
                if(object.update == null) stat.setString(2, null);
                else stat.setString(2, object.update);
                if(object.edition == null) stat.setString(3, null);
                else stat.setString(3, object.edition);
                if(object.language == null) stat.setString(4, null);
                else stat.setString(4, object.language);
                if(object.swEdition == null) stat.setString(5, null);
                else stat.setString(5, object.swEdition);
                if(object.targetSw == null) stat.setString(6, null);
                else stat.setString(6, object.targetSw);
                if(object.targetHw == null) stat.setString(7, null);
                else stat.setString(7, object.targetHw);
                if(object.other == null) stat.setString(8, null);
                else stat.setString(8, object.other);
                stat.executeUpdate();
            }

            // Closing the database connection
            db.close();
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
    }

    /**
     * This method's purpose is to update the database full of CPE objects so that it can be up-to-date
     * <p>
     * This method loads all the objects from the up-to-date file,
     * then it always loads all the objects with the same one vendor from the database (vendor by vendor)
     * and compares them to objects with the same vendor from the up-to-date file,
     * then it adds all non-duplicate objects into the database
     *
     * @throws ClassNotFoundException
     * @throws SQLException
     * @throws IOException
     */
    public static void comparingForUpdate() {

        // list of objects from up-to-date file
        ArrayList<CPEobject> compared_objects = stringArrayListToObjectArraylist();

        // ArrayList which will contain all the vendors that exist in the up-to-date file
        ArrayList<String> obj_vendors = new ArrayList<>();

        // DB connection
        ArrayList<String> url_conn = new ArrayList<>();

        // This block of code takes the connection url from the separate file and puts it into the url_conn's 0 index
        try (BufferedReader br = new BufferedReader(new FileReader("exclude/dbconnection.txt"))) {
            for (String line; (line = br.readLine()) != null; ) {
                url_conn.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // This for cycle fills the obj_vendor ArrayList with all vendors that exist in the up-to-date file
        for (CPEobject obj : compared_objects) {

            if (obj_vendors.contains(obj.vendor)) ;
            else obj_vendors.add(obj.vendor) ;
        }

        // This for cycle is for the purpose to go through all the vendors that exist in the up-to-date file one by one
        for (String vendor : obj_vendors) {

            try {

                // list of CPE objects from DB with the specific vendor
                ArrayList<CPEobject> objects_to_compare = new ArrayList<>();
                // list of CPE objects from up-to-date file with the specific vendor
                ArrayList<CPEobject> compared_objects_vendor = new ArrayList<>();

                /**
                 * This for cycle fills the ArrayList compared_objects_vendor with all CPE objects that have the
                 * current specific vendor from the up-to-date file
                 */
                for (CPEobject obj : compared_objects) {
                    if (obj.vendor.equals(vendor)) compared_objects_vendor.add(obj) ;

                }

                Class.forName("org.postgresql.Driver");

                // Connection to the database
                db = DriverManager.getConnection(url_conn.get(0));

                /**
                 * This for cycle fills the ArrayList compared_objects_vendor with all CPE objects that have the
                 * current specific vendor from the database
                 */
                Statement stat = db.createStatement();
                ResultSet result = stat.executeQuery("SELECT * FROM cpe_match_feed_objects WHERE vendor = '" + vendor + "'");
                while (result.next()) {
                    CPEobject obj_to_compare = new CPEobject(result.getString(2), result.getString(3), result.getString(4), result.getString(5), result.getString(6), result.getString(7), result.getString(8), result.getString(9), result.getString(10), result.getString(11));
                    objects_to_compare.add(obj_to_compare);
                }

                /**
                 * This block of code compares all objects with the current specific vendor from the up-to-date file with
                 * all objects with the current specific vendor from the database.
                 * It uses the compare() method which can be seen at the bottom of this class.
                 */
                boolean duplicity;
                for (CPEobject new_obj : compared_objects_vendor) {
                    duplicity = false;
                    for (CPEobject old_obj : objects_to_compare) {
                        if (new_obj.compare(old_obj)) {
                            duplicity = true;
                            break;
                        }
                    }

                    // If the object isn't in the database (its new), its added into the database
                    if (!duplicity) {
                        // PreparedStatement is used to handle null values
                        PreparedStatement addstat = db.prepareStatement("INSERT INTO cpe_match_feed_objects (vendor, product, version, update, edition, language, swedition, targetsw, targethw, other) "
                                + "VALUES ('"+new_obj.vendor+"','"+new_obj.product+"',?,?,?,?,?,?,?,?)");
                        if(new_obj.version == null) addstat.setString(1,null);
                        else addstat.setString(1, new_obj.version);
                        if(new_obj.update == null) addstat.setString(2, null);
                        else addstat.setString(2, new_obj.update);
                        if(new_obj.edition == null) addstat.setString(3, null);
                        else addstat.setString(3, new_obj.edition);
                        if(new_obj.language == null) addstat.setString(4, null);
                        else addstat.setString(4, new_obj.language);
                        if(new_obj.swEdition == null) addstat.setString(5, null);
                        else addstat.setString(5, new_obj.swEdition);
                        if(new_obj.targetSw == null) addstat.setString(6, null);
                        else addstat.setString(6, new_obj.targetSw);
                        if(new_obj.targetHw == null) addstat.setString(7, null);
                        else addstat.setString(7, new_obj.targetHw);
                        if(new_obj.other == null) addstat.setString(8, null);
                        else addstat.setString(8, new_obj.other);
                        addstat.executeUpdate();
                    }
                }

                // Closing connection to the database
                db.close();

            } catch (SQLException | ClassNotFoundException ex) {
                ex.printStackTrace();
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
     * Compares to input_obj
     *
     * @param input_obj Object that is compared with
     * @return If the CPE objects are the same or not (true or false)
     *
     * The String "null" values are there because taking a null value from database puts it into the object in this form
     */
    public boolean compare(CPEobject input_obj) {

        // Comparing vendor parameter of compared objects
        if (this.vendor.compareTo(input_obj.vendor) == 0) ;
        else {
            return false;
        }

        // Comparing product parameter of compared objects
        if (this.product.compareTo(input_obj.product) == 0) ;
        else {
            return false;
        }

        // Comparing version parameter of compared objects
        if (this.version == null || input_obj.version == null) {
            if (this.version == null && input_obj.version == null) ;
            else {
                return false;
            }
        } else if (this.version.compareTo(input_obj.version) == 0) ;
        else {
            return false;
        }

        // Comparing update parameter of compared objects
        if (this.update == null || input_obj.update == null) {
            if (this.update == null && input_obj.update == null) ;
            else {
                return false;
            }
        } else if (this.update.compareTo(input_obj.update) == 0) ;
        else {
            return false;
        }

        // Comparing edition parameter of compared objects
        if (this.edition == null || input_obj.edition == null) {
            if (this.edition == null && input_obj.edition == null) ;
            else {
                return false;
            }
        } else if (this.edition.compareTo(input_obj.edition) == 0) ;
        else {
            return false;
        }

        // Comparing language parameter of compared objects
        if (this.language == null || input_obj.language == null) {
            if (this.language == null && input_obj.language == null) ;
            else {
                return false;
            }
        } else if (this.language.compareTo(input_obj.language) == 0) ;
        else {
            return false;
        }

        // Comparing swEdition parameter of compared objects
        if (this.swEdition == null || input_obj.swEdition == null) {
            if (this.swEdition == null && input_obj.swEdition == null) ;
            else {
                return false;
            }
        } else if (this.swEdition.compareTo(input_obj.swEdition) == 0) ;
        else {
            return false;
        }

        // Comparing targetSw parameter of compared objects
        if (this.targetSw == null || input_obj.targetSw == null) {
            if (this.targetSw == null && input_obj.targetSw == null) ;
            else {
                return false;
            }
        } else if (this.targetSw.compareTo(input_obj.targetSw) == 0) ;
        else {
            return false;
        }

        // Comparing targetHw parameter of compared objects
        if (this.targetHw == null || input_obj.targetHw == null) {
            if (this.targetHw == null && input_obj.targetHw == null) ;
            else {
                return false;
            }
        } else if (this.targetHw.compareTo(input_obj.targetHw) == 0) ;
        else {
            return false;
        }

        // Comparing other parameter of compared objects
        if (this.other == null || input_obj.other == null) {
            if (this.other == null && input_obj.other == null) ;
            else {
                return false;
            }
        } else if (this.other.compareTo(input_obj.other) == 0) ;
        else {
            return false;
        }

        return true;

    }
}
