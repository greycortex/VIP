package basic_mitre.cpe;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.persistence.*;
import java.io.*;
import java.util.*;

/**
 * This class represents a normal CPE object (vendor, product, version, ...)
 * <p>
 * It can read from file, create objects representing CPE objects and complex CPE objects and insert them into the database
 * <p>
 * It also can create a normal CPE object from cpe23Uri String and return it
 * <p>
 *
 * @author Tomas Bozek (XarfNao)
 */
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
@Entity(name = "cpe")
@Table(name = "cpe", schema = "mitre", indexes = @Index(name = "cpe_vendor_product_idx", columnList = "vendor, product"))
public class CPEobject implements Serializable {

    public CPEobject(){ } // default constructor

    @Id
    @Column(unique = true, name = "id")
    protected String cpe_id;
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

    @OneToMany(mappedBy = "cpe")
    protected List<CPEnodeToCPE> node_to_compl;

    @ManyToMany(mappedBy = "cpe")
    protected List<CPEcomplexObj> compl_cpe;

    public String getCpe_id() {
        return cpe_id;
    }

    public void setCpe_id(String cpe_id) {
        this.cpe_id = cpe_id;
    }

    /**
     * @param cpe_id    CPE ID - cpeUri String
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
    public CPEobject(String cpe_id, String vendor, String product, String version, String update, String edition, String language,
                     String swEdition, String targetSw, String targetHw, String other) { // not a dumb constructor

        this.cpe_id = cpe_id;
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

    // Constructor for specific input - String Array and id - useful later on
    public CPEobject(String cpe_id, String[] splitstr) {

        this.cpe_id = cpe_id;
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
     * This method's purpose is to take cpeUri line and create basic CPE object
     *
     * @param cpeUri line which is used to create a final basic CPE object
     * @return basic CPE object
     */
    public static CPEobject cpeUriToObject(String cpeUri) {

        // This Array is filled with parts of the cpeUri String (separates by ":")
        String[] splitstr = cpeUri.split("[:]", -1);

        // Used for creating CPE id later on
        String[] splitstrid = cpeUri.split("[:]", -1);

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

            //    splitstr[i] = splitstr[i].replace("'", "''");
                splitstr[i] = splitstr[i].replace("\\\\", "\\");
            }
        }

        // This block of code removes the apostrophes that can appear at the end of the cpeUri String
        if (splitstr[12] != null) {
            splitstr[12] = splitstr[12].replace(",", "");
            splitstr[12] = splitstr[12].replace("\"", "");
            splitstr[12] = splitstr[12].replace("}", "");
        }

        // Creating CPE id
        for (int i = 0; i < splitstrid.length; i++){
            if (splitstrid[i].equals("*\",") || splitstrid[i].equals("*\"") || splitstrid[i].equals("*")) {
                splitstrid[i] = "";
            }
            if (splitstrid[i] != null && !(splitstrid[i].equals(""))) {
            //    splitstr[i] = splitstr[i].replace("'", "''");
                splitstrid[i] = splitstrid[i].replace("\\\\", "\\");
            }
        }

        String cpe_id = splitstrid[0] + ":" + splitstrid[1] + ":" + splitstrid[2] + ":" + splitstrid[3] + ":" + splitstrid[4]
                + ":" + splitstrid[5] + ":" + splitstrid[6] + ":" + splitstrid[7] + ":" + splitstrid[8] + ":" + splitstrid[9]
                + ":" + splitstrid[10] + ":" + splitstrid[11] + ":" + splitstrid[12];

        // Finally creates a new CPE object using changed parts of the splitstr Array
        return new CPEobject(cpe_id, splitstr);
    }

    /**
     * @param file path to .json file with CPE dictionary data (CPE match feed file)
     *
     * @return List that contains parsed lines (Strings) from the CPE feed file
     */
    public static List<String> parseIntoLines(String file) { // file - https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip
        System.out.println("Parsing of basic CPE objects from match feed file started");
        // List which will contain parsed lines from the CPE file
        List<String> cpe23urilines = new ArrayList<>();

        // This block of code goes through the selected file line by line and add the lines that contain "cpe23uri" to the cpe23urilines List
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
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
     * @return List that contains basic CPE objects without duplicates made from the cpe23uri lines List returned by the parseIntoLines() method
     *
     * @param file path to .json file with CPE dictionary data (CPE match feed file)
     */
    public static List<CPEobject> linesIntoReadyList(String file) { // file - https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip
        // Defining the object List
        List<CPEobject> obj_list = new ArrayList<>();

        // Taking the lines returned by the parserToLineArrayList() method
        List<String> cpe23uriliness = parseIntoLines(file);

        // We go line by line (Object by Object)
        for (String line : cpe23uriliness) {

            // This Array is filled with parts of the line (separates by ":")
            String[] splitstr = line.split("[:]", -1);

            // Used for creating CPE id later on
            String[] splitstrid = line.split("[:]", -1);

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

                //    splitstr[i] = splitstr[i].replace("'", "''");
                    splitstr[i] = splitstr[i].replace("\\\\", "\\");
                }
            }

            // This block of code removes the apostrophes that can appear at the end of the line
            if (splitstr[13] != null) {
                splitstr[13] = splitstr[13].replace(",", "");
                splitstr[13] = splitstr[13].replace("\"", "");
                splitstr[13] = splitstr[13].replace("}", "");
            }

            // Creating final String Array which will be used for creation of a new CPE object
            String[] finalSplitstr = {splitstr[1], splitstr[2], splitstr[3], splitstr[4], splitstr[5], splitstr[6], splitstr[7], splitstr[8], splitstr[9], splitstr[10], splitstr[11], splitstr[12], splitstr[13]};

            // Creating CPE id
            for (int i = 0; i < splitstrid.length; i++){
                if (splitstrid[i].equals("*\",") || splitstrid[i].equals("*\"") || splitstrid[i].equals("*")) {
                    splitstrid[i] = "";
                }
                if (splitstrid[i] != null && !(splitstrid[i].equals(""))) {
                //    splitstr[i] = splitstr[i].replace("'", "''");
                    splitstrid[i] = splitstrid[i].replace("\\\\", "\\");
                }
            }

            String[] splitfirst = splitstrid[1].split("\"");
            String[] splitlast = splitstrid[13].split("\"");

            String cpe_id = splitfirst[1] + ":" + splitstrid[2] + ":" + splitstrid[3] + ":" + splitstrid[4] + ":" + splitstrid[5]
                    + ":" + splitstrid[6] + ":" + splitstrid[7] + ":" + splitstrid[8] + ":" + splitstrid[9] + ":" + splitstrid[10]
                    + ":" + splitstrid[11] + ":" + splitstrid[12] + ":" + splitlast[0];

            // Finally creates a new CPE object using changed parts of the splitstr Array
            CPEobject obj = new CPEobject(cpe_id, finalSplitstr);
            obj_list.add(obj);
        }
        // Returns List that contains CPE objects made from the cpe23uri lines List returned by the parserToLineArrayList() method
        System.out.println("Parsing of basic CPE objects from match feed file done");

        // Removing duplicates
        System.out.println("Duplicates of basic CPE objects removal started, current object count: "+obj_list.size());

        // Removing duplicates by creating a LinkedHashSet
        ArrayList<CPEobject> return_objs = new ArrayList<CPEobject>(new LinkedHashSet<CPEobject>(obj_list));

        System.out.println("Duplicates of basic CPE objects removal done, current object count: "+return_objs.size());

        // Returns List of CPE objects from the up-to-date file without duplicates
        return return_objs;
    }

    /**
     * This method parses complex CPE objects from the up-to-date file and puts them into database with right relations between objects
     *
     * @param file path to .json file with CPE dictionary data (CPE match feed file)
     * @param sf   object needed to get hibernate Session Factory and to work with database
     */
    public static void CPEcomplexIntoDatabase(String file, SessionFactory sf){ // file - https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip

        // Opening session and beginning transaction
        Session session = sf.openSession();
        Transaction txv = session.beginTransaction();

        int count = 0;

        // Parsing JSON file
        JSONParser parser = new JSONParser();

        try (Reader reader = new FileReader(file)){ // file - https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip

            JSONObject jsonObject = (JSONObject) parser.parse(reader);

            /**
             * Getting to "matches" json array and iterating through him (array of CPE objects with various relations)
             */
            JSONArray matches = (JSONArray) jsonObject.get("matches");
            Iterator<JSONObject> iterator = matches.iterator();

            while (iterator.hasNext()){

                // Getting CPE item
                JSONObject cpe_item = iterator.next();

                // Recognizing if its complex CPE object
                if (cpe_item.get("versionStartExcluding") != null || cpe_item.get("versionStartIncluding") != null
                        || cpe_item.get("versionEndExcluding") != null || cpe_item.get("versionEndIncluding") != null){

                    // Ensuring optimalization
                    if (count % 500 == 0){
                        txv.commit();
                        txv = session.beginTransaction();
                    }
                    count++;

                    // Getting basic cpeUri attribute
                    String cpeUri = (String) cpe_item.get("cpe23Uri");
                    String versionStartExcluding = null;
                    String versionStartIncluding = null;
                    String versionEndExcluding = null;
                    String versionEndIncluding = null;

                    // Getting eventual attributes
                    if (cpe_item.get("versionStartExcluding") != null){
                        versionStartExcluding = (String) cpe_item.get("versionStartExcluding");
                        versionStartExcluding = versionStartExcluding.replace("\\\\","\\");
                    }
                    if (cpe_item.get("versionStartIncluding") != null){
                        versionStartIncluding = (String) cpe_item.get("versionStartIncluding");
                        versionStartIncluding = versionStartIncluding.replace("\\\\","\\");
                    }
                    if (cpe_item.get("versionEndExcluding") != null){
                        versionEndExcluding = (String) cpe_item.get("versionEndExcluding");
                        versionEndExcluding = versionEndExcluding.replace("\\\\","\\");
                    }
                    if (cpe_item.get("versionEndIncluding") != null){
                        versionEndIncluding = (String) cpe_item.get("versionEndIncluding");
                        versionEndIncluding = versionEndIncluding.replace("\\\\","\\");
                    }

                    // Creating complex CPE object
                    CPEcomplexObj complex_obj = CPEcomplexObj.getInstanceFromCPE(CPEobject.cpeUriToObject(cpeUri), null,
                            versionStartExcluding, versionEndExcluding, versionStartIncluding, versionEndIncluding);

                    // Getting all basic CPE objects that are related to the specific complex CPE object
                    JSONArray basic_cpes_to_relate = (JSONArray) cpe_item.get("cpe_name");
                    if (!basic_cpes_to_relate.isEmpty()){
                        complex_obj.setCpe_objs(new ArrayList<>());

                        Iterator<JSONObject> iterator_basic = basic_cpes_to_relate.iterator();

                        while (iterator_basic.hasNext()){

                            JSONObject basic_cpe_json = iterator_basic.next();

                            if (basic_cpe_json.get("cpe23Uri") != null){

                                // Getting cpeUri String of a basic CPE object
                                String basic_cpe_uri = (String) basic_cpe_json.get("cpe23Uri");

                                // Used for creating CPE id
                                String[] splitstrid = basic_cpe_uri.split("[:]", -1);

                                // Creating CPE id
                                for (int i = 0; i < splitstrid.length; i++){
                                    if (splitstrid[i].equals("*\",") || splitstrid[i].equals("*\"") || splitstrid[i].equals("*")) {
                                        splitstrid[i] = "";
                                    }
                                    if (splitstrid[i] != null && !(splitstrid[i].equals(""))) {
                                    //    splitstr[i] = splitstr[i].replace("'", "''");
                                        splitstrid[i] = splitstrid[i].replace("\\\\", "\\");
                                    }
                                }
                                String cpe_id = splitstrid[0] + ":" + splitstrid[1] + ":" + splitstrid[2] + ":" + splitstrid[3] + ":" + splitstrid[4]
                                        + ":" + splitstrid[5] + ":" + splitstrid[6] + ":" + splitstrid[7] + ":" + splitstrid[8] + ":" + splitstrid[9]
                                        + ":" + splitstrid[10] + ":" + splitstrid[11] + ":" + splitstrid[12];

                                // Getting related basic CPE object from the database and relating it to the specific complex CPE object
                                CPEobject cpe_to_add = (CPEobject) session.get(CPEobject.class, cpe_id);
                                complex_obj.getCpe_objs().add(cpe_to_add);
                            }
                        }
                    }
                    // creating unique ID
                    if (complex_obj.getVersion_start_including() != null) {
                        complex_obj.setCpe_id(complex_obj.getCpe_id() + "#star_in_" + complex_obj.getVersion_start_including());
                    }
                    if (complex_obj.getVersion_start_excluding() != null) {
                        complex_obj.setCpe_id(complex_obj.getCpe_id() + "#star_ex_" + complex_obj.getVersion_start_excluding());
                    }
                    if (complex_obj.getVersion_end_including() != null) {
                        complex_obj.setCpe_id(complex_obj.getCpe_id() + "#end_in_" + complex_obj.getVersion_end_including());
                    }
                    if (complex_obj.getVersion_end_excluding() != null) {
                        complex_obj.setCpe_id(complex_obj.getCpe_id() + "#end_ex_" + complex_obj.getVersion_end_excluding());
                    }
                    // If the object doesn't exist, it will be put into database
                    if (session.get(CPEcomplexObj.class, complex_obj.getCpe_id()) == null){
                        session.save(complex_obj);
                    }
                }
            }
        } catch (IOException | ParseException e){
            e.printStackTrace();
        }
        // Commiting transaction, closing session and session factory
        if (txv.isActive()) txv.commit();
        if (session.isOpen()) session.close();
    }

    /**
     * This method's purpose is to put basic CPE objects into database so that it can be up-to-date
     * <p>
     * This method loads all basic CPE objects from the up-to-date file and puts them into database,
     * it also calls the CPEcomplexIntoDatabase() method which puts all complex CPE objects from the up-to-date file
     * into database with right relations between objects
     *
     * @param file path to .json file with CPE dictionary data (CPE match feed file)
     * @param sf   object needed to get hibernate Session Factory and to work with database
     */
    public static void putIntoDatabase(String file, SessionFactory sf) { // file - https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip
        // list of objects from up-to-date file
        List<CPEobject> compared_objects = linesIntoReadyList(file);

        System.out.println("Filling database with CPE objects started");

        // Creating session
        Session session = sf.openSession();

        // Measuring, how long it will take to put basic CPE objects into database
        long start_time = System.currentTimeMillis();

        // Putting basic CPE objects into database
        // Beginning transaction
        Transaction txv = session.beginTransaction();
        for (CPEobject obj : compared_objects){
            session.save(obj);
        }
        // Ending transaction, session and session factory
        txv.commit();
        session.close();
        if ((System.currentTimeMillis()-start_time) > 60000) System.out.println("Filling database with CPE objects from match feed file done, time elapsed: "+((System.currentTimeMillis()-start_time)/60000)+" minutes");
        else System.out.println("Filling database with CPE objects from match feed file done, time elapsed: "+((System.currentTimeMillis()-start_time)/1000)+" seconds");

        // Measuring, how long it will take to put complex CPE objects into database
        start_time = System.currentTimeMillis();
        System.out.println("Filling database with complex CPE objects from match feed file started");

        // Calling method CPEcomplexIntoDatabase() which will put all complex CPE objects from match feed file into database with right relations
        CPEcomplexIntoDatabase(file, sf); // file - https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip

        if ((System.currentTimeMillis()-start_time) > 60000) System.out.println("Filling database with complex CPE objects from match feed file done, time elapsed: "+((System.currentTimeMillis()-start_time)/60000)+" minutes");
        else System.out.println("Filling database with complex CPE objects from match feed file done, time elapsed: "+((System.currentTimeMillis()-start_time)/1000)+" seconds");
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
        return Objects.hash(cpe_id);
    }

    @Override
    public String toString() {
        return "CPEobject{"
                + "cpe_id='" + cpe_id + '\''
                + ", vendor='" + vendor + '\''
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
