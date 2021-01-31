package mitre.cpe;

import javax.persistence.*;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.cfg.Configuration;
import org.hibernate.service.ServiceRegistry;
import org.hibernate.service.ServiceRegistryBuilder;

import java.io.*;
import java.util.*;

/**
 * This class represents a normal CPE object (vendor, product, version, ...)
 * <p>
 * It can read from file, create objects representing CPE objects and insert them into the database including updates
 * <p>
 * It also can create a normal CPE object from cpe23Uri String and return it
 *
 * @author Tomas Bozek (XarfNao)
 */

@Entity
@Table(name="cpeobject")
// @Cacheable
// @Cache(usage=CacheConcurrencyStrategy.READ_WRITE)
public class CPEobject {

    public CPEobject(){ } // default constructor

    /**
     * Automatic ID
     */
    @Id
    @Column(unique = true)
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    protected Long id;

    protected String vendor;
    protected String product;
    protected String version;

    @Column(name="`Update`")
    protected String update;
    protected String edition;
    protected String language;
    protected String swEdition;
    protected String targetSw;
    protected String targetHw;
    protected String other;

    /**
     * @param vendor    vendor attribute
     * @param product   product attribute
     * @param version   version attribute
     * @param update    update attribute
     * @param edition   edition attribute
     * @param language  language attribute
     * @param swEdition software edition attribute
     * @param targetSw  target software attribute
     * @param targetHw  target hardware attribute
     * @param other     other attribute
     */
    public CPEobject(String vendor, String product, String version, String update, String edition, String language,
                     String swEdition, String targetSw, String targetHw, String other) { // not a dumb constructor

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

    // Constructor for specific input - String Array - useful later on
    public CPEobject(String[] splitstr) {

        this.id = null;
        this.vendor = splitstr[3];
        this.product = splitstr[4];
        this.version = splitstr[5];
        this.update = splitstr[6];
        this.edition = splitstr[7];
        this.language = splitstr[8];
        this.swEdition = splitstr[9];
        this.targetSw = splitstr[10];
        this.targetHw = splitstr[11];
        this.other = splitstr[12];
    }

    /**
     * This method's purpose is to take cpeUri line and create an sql-friendly normal CPE object
     *
     * @param cpeUri line which is used to create a final normal CPE object
     * @return an sql-friendly normal CPE object
     */
    public static CPEobject cpeUriToObject(String cpeUri) {
        // This Array is filled with parts of the cpeUri String (separates by ":")
        String[] splitstr = cpeUri.split(":");

        /**
         * This for cycle goes through each part of the splitstr Array and changes its parts so that they are
         * more database and search friendly and have a better form in general
         */
        for (int i = 0; i < splitstr.length; i++) {
            // This replaces all the "*" characters (which mean empty parameters)
            if (splitstr[i].equals("*") || splitstr[i].equals("*\",") || splitstr[i].equals("*\"")) {
                splitstr[i] = null;
            }

            /**
             * This block of code replaces all SQL-not-friendly apostrophes with sql-friendly apostrophes,
             * it also removes backslashes in weird places
             */
            if (splitstr[i] != null) {

            //    splitstr[i] = splitstr[i].replaceAll("'", "''"); ---
                splitstr[i] = splitstr[i].replaceAll("\\\\", "");
            }
        }

        // This block of code removes the apostrophes that can appear at the end of the cpeUri String
        if (splitstr[12] != null) {
            splitstr[12] = splitstr[12].replace("\",", "");
            splitstr[12] = splitstr[12].replace("\"", "");
        }

        // Finally creates a new CPE object using changed parts of the splitstr Array
        return new CPEobject(splitstr);
    }

    /**
     * @return List that contains parsed lines (Strings) from the CPE feed file
     * @throws IOException
     */
    public static List<String> parserToLineArrayList() {
        System.out.println("Parsing of CPE objects started");
        // List which will contain parsed lines from the CPE file
        List<String> cpe23urilines = new ArrayList<>();

        // This block of code goes through the selected file line by line and add the lines that contain "cpe23uri" to the cpe23urilines List
        try (BufferedReader br = new BufferedReader(new FileReader("exclude/nvdcpematch-1.0.json"))) {
            for (String line; (line = br.readLine()) != null; ) {
                if (line.contains("cpe23Uri")) {
                    cpe23urilines.add(line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Returns List that contains parsed lines (Strings) from the CPE feed file
        return cpe23urilines;
    }

    /**
     * @return List that contains CPE objects made from the cpe23uri lines List returned by the parserToLineArrayList() method
     */
    public static List<CPEobject> stringArrayListToObjectArraylist() {
        // Defining the object List
        List<CPEobject> obj_list = new ArrayList<>();

        // Taking the lines returned by the parserToLineArrayList() method
        List<String> cpe23uriliness = parserToLineArrayList();

        // We go line by line (Object by Object)
        for (String line : cpe23uriliness) {

            // This Array is filled with parts of the line (separates by ":")
            String[] splitstr = line.split(":");

            /**
             * This for cycle goes through each part of the splitstr Array and changes its parts so that they are
             * more database and search friendly and have a better form in general
             */
            for (int i = 0; i < splitstr.length; i++) {
                // This replaces all the "*" characters (which mean empty parameters)
                if (splitstr[i].equals("*") || splitstr[i].equals("*\",") || splitstr[i].equals("*\"")) {
                    splitstr[i] = null;
                }

                /**
                 * This block of code replaces all the SQL-not-friendly apostrophes with a sql-friendly apostrophes,
                 * it also removes backslashes in weird places
                 */
                if (splitstr[i] != null) {

                //    splitstr[i] = splitstr[i].replace("'", "''"); ---
                    splitstr[i] = splitstr[i].replace("\\\\", "");
                }
            }

            // This block of code removes the apostrophes that can appear at the end of the line
            if (splitstr[13] != null) {
                splitstr[13] = splitstr[13].replace("\",", "");
                splitstr[13] = splitstr[13].replace("\"", "");
            }

            // Creating final String Array which will be used for creation of a new CPE object
            String[] finalSplitstr = {splitstr[1], splitstr[2], splitstr[3], splitstr[4], splitstr[5], splitstr[6], splitstr[7], splitstr[8], splitstr[9], splitstr[10], splitstr[11], splitstr[12], splitstr[13]};

            // Finally creates a new CPE object using changed parts of the splitstr Array
            CPEobject obj = new CPEobject(finalSplitstr);
            obj_list.add(obj);
        }
        // Returns List that contains CPE objects made from the cpe23uri lines List returned by the parserToLineArrayList() method
        System.out.println("Parsing of CPE objects done");
        return obj_list;
    }

    // This method's purpose is to remove duplicates from the List returned by the stringArrayListToObjectArraylist() method
    public static List<CPEobject> removeDuplicates() {
        // Takes all objects returned by the stringArrayListToObjectArraylist() method
        List<CPEobject> all_objs = stringArrayListToObjectArraylist();

        System.out.println("Duplicates of CPE objects removal started, current object count: "+all_objs.size());

        // Removing duplicates by creating a LinkedHashSet
        ArrayList<CPEobject> return_objs = new ArrayList<CPEobject>(new LinkedHashSet<CPEobject>(all_objs));

        System.out.println("Duplicates of CPE objects removal done, current object count: "+return_objs.size());
        // Returns List of CPE objects from the up-to-date file without duplicates
        return return_objs;
    }

    /**
     * This method's purpose is to update the database full of CPE objects so that it can be up-to-date
     * <p>
     * This method loads all the objects from the up-to-date file and puts them into database or it updates the database
     *
     */
    public static void putIntoDatabase() {
        // list of objects from up-to-date file
        List<CPEobject> compared_objects = removeDuplicates();

        // Measuring, how long it will take to update the table in database
        long start_time = System.currentTimeMillis();

        System.out.println("Actualization of basic CPE objects in database started");

        // List which will contain all the vendors that exist in the up-to-date file
        List<String> obj_vendors = new ArrayList<>();

        // Count of vendors gone through from the last print of a CPE object and from the last refresh of the session
        int display = 0;

        // Creating connection and session
        Configuration con = new Configuration().configure().addAnnotatedClass(CPEobject.class);
        ServiceRegistry reg = new ServiceRegistryBuilder().applySettings(con.getProperties()).buildServiceRegistry();
        SessionFactory sf = con.buildSessionFactory(reg);
        Session session = sf.openSession();

        // If the cpeobject table is empty, the method doesn't compare
        Query q = session.createQuery("from CPEobject");
        q.setMaxResults(10);
        if (q.list().isEmpty()){
            // Beginning transaction
            Transaction txv = session.beginTransaction();
            System.out.println("Database table empty, comparing not included");
            for (CPEobject obj : compared_objects){
                session.save(obj);
            }
            // Ending transaction and session
            txv.commit();
            session.close();
        }
        // If the cpeobject table isn't empty, the method does compare
        else{
            System.out.println("Database table not empty, comparing included");
            // Ending session
            session.close();
            // Beginning session
            Session sessionc = sf.openSession();
            // This for cycle fills the obj_vendor List with all vendors that exist in the up-to-date file
            for (CPEobject obj : compared_objects) {
                if (!(obj_vendors.contains(obj.vendor))) obj_vendors.add(obj.vendor);
            }
            // This for cycle is for the purpose to go through all the vendors that exist in the up-to-date file one by one
            for (String vendor : obj_vendors) {
                display++;
                try {
                    // list of CPE objects from up-to-date file with the specific vendor
                    List<CPEobject> compared_objects_vendor = new ArrayList<>();

                    /**
                     * This for cycle fills the List compared_objects_vendor with all CPE objects that have the
                     * current specific vendor from the up-to-date file
                     */
                    for (CPEobject obj : compared_objects) {
                        if (obj.vendor.equals(vendor)) compared_objects_vendor.add(obj);
                    }

                    // Print one of many CPE objects
                    if (display == 500) {
                        System.out.println(compared_objects_vendor.get(0));
                        display = 0;
                        // Ending session
                        sessionc.close();
                        // Beginning session
                        sessionc = sf.openSession();
                    }
                    // Beginning transaction
                    Transaction txv = sessionc.beginTransaction();

                    // Controlling if the vendor String is sql-friendly
                    vendor = vendor.replaceAll("'", "''");

                    // Getting CPE objects with current specific vendor from the database
                    Query qv = sessionc.createQuery("from CPEobject where vendor = '" + vendor + "'");

                    // list of CPE objects from DB with the specific vendor
                    List<CPEobject> objects_to_compare = (List<CPEobject>) qv.list(); // Default constructor calling

                    /**
                     * This block of code compares all objects with the current specific vendor from the up-to-date file with
                     * all objects with the current specific vendor from the database.
                     * It uses the compare() method which can be seen at the bottom of this class.
                     */
                    boolean duplicity;
                    for (CPEobject new_obj : compared_objects_vendor) {
                        duplicity = false;
                        for (CPEobject old_obj : objects_to_compare) {
                            if (new_obj.equals(old_obj)) {
                                duplicity = true;
                                break;
                            }
                        }
                        // If the object isn't in the database (its new), its added into the database
                        if (!(duplicity)) {
                            sessionc.save(new_obj);
                        }
                    }
                    // Ending transaction
                    txv.commit();
                } catch (Exception ex){
                    ex.printStackTrace();
                }
            }
            // If the session is opened at the end, it will be closed
            if (sessionc.isOpen()) sessionc.close();
        }
        if ((System.currentTimeMillis()-start_time) > 60000) System.out.println("Actualization of basic CPE objects in database done, time elapsed: "+((System.currentTimeMillis()-start_time)/60000)+" minutes");
        else System.out.println("Actualization of basic CPE objects in database done, time elapsed: "+((System.currentTimeMillis()-start_time)/1000)+" seconds");
    }

    /**
     * Compares to input_obj
     *
     * @param obj Object that is compared with
     * @return If the CPE objects are the same or not (true or false)
     */
    @Override
    public boolean equals(Object obj) {
        // Controlling if the object is CPEobject
        if (!(obj instanceof CPEobject)) return false;
        CPEobject input_obj = (CPEobject) obj;
        // Comparing vendor parameter of compared objects
        if (!(this.vendor.compareTo(input_obj.vendor) == 0)) return false;

        // Comparing product parameter of compared objects
        if (!(this.product.compareTo(input_obj.product) == 0)) return false;

        // Comparing version parameter of compared objects
        if (this.version == null || input_obj.version == null) {
            if (!(this.version == null && input_obj.version == null)) return false;
        } else if (!(this.version.compareTo(input_obj.version) == 0)) return false;

        // Comparing update parameter of compared objects
        if (this.update == null || input_obj.update == null) {
            if (!(this.update == null && input_obj.update == null)) return false;
        } else if (!(this.update.compareTo(input_obj.update) == 0)) return false;

        // Comparing edition parameter of compared objects
        if (this.edition == null || input_obj.edition == null) {
            if (!(this.edition == null && input_obj.edition == null)) return false;
        } else if (!(this.edition.compareTo(input_obj.edition) == 0)) return false;

        // Comparing language parameter of compared objects
        if (this.language == null || input_obj.language == null) {
            if (!(this.language == null && input_obj.language == null)) return false;
        } else if (!(this.language.compareTo(input_obj.language) == 0)) return false;

        // Comparing swEdition parameter of compared objects
        if (this.swEdition == null || input_obj.swEdition == null) {
            if (!(this.swEdition == null && input_obj.swEdition == null)) return false;
        } else if (!(this.swEdition.compareTo(input_obj.swEdition) == 0)) return false;

        // Comparing targetSw parameter of compared objects
        if (this.targetSw == null || input_obj.targetSw == null) {
            if (!(this.targetSw == null && input_obj.targetSw == null)) return false;
        } else if (!(this.targetSw.compareTo(input_obj.targetSw) == 0)) return false;

        // Comparing targetHw parameter of compared objects
        if (this.targetHw == null || input_obj.targetHw == null) {
            if (!(this.targetHw == null && input_obj.targetHw == null)) return false;
        } else if (!(this.targetHw.compareTo(input_obj.targetHw) == 0)) return false;

        // Comparing other parameter of compared objects
        if (this.other == null || input_obj.other == null) {
            if (!(this.other == null && input_obj.other == null)) return false;
        } else if (!(this.other.compareTo(input_obj.other) == 0)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return Objects.hash(vendor, product, version, update, edition, language, swEdition, targetSw, targetHw, other);
    }

    @Override
    public String toString() {
        return "CPEobject{"
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
}
