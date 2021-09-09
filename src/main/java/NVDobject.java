import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.jdbc.Work;
import org.hibernate.service.ServiceRegistry;

import javax.persistence.Query;
import java.io.*;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * This class' purpose is to connect all methods that put various objects into database so that the needed operation will be executed
 *
 * @author Tomas Bozek (XarfNao)
 */
public class NVDobject {

    // booleans used for finding out how complex the structure of the database is
    public static boolean db_exists = false;
    public static boolean db_extended = false;

    /**
     * This method's purpose is to quickly update CVE and CPE objects in the database
     * It uses the quickUpdateCore() methods from CVEobject classes for this purpose
     * It also exports all valuable SQL queries about database data change into
     * file (its path is given in output_file argument)
     *
     * @param update_file path to .json file with CVE objects - "modified" file containing recently changed data
     * @param config_file path to Hibernate configuration file with SQL query output turned on
     * @param output_file path to file that will be filled with all valuable SQL queries
     */
    public static void quickUpdate(String update_file, String config_file, String output_file) {
        // Opening session and controlling if database structure exists and if its extended or not
        Configuration control_conf = new Configuration().configure();
        ServiceRegistry control_reg = new StandardServiceRegistryBuilder().applySettings(control_conf.getProperties()).build();
        SessionFactory control_sf = control_conf.buildSessionFactory(control_reg);
        Session control_sess = control_sf.openSession();

        control_sess.doWork(new Work() {
            @Override
            public void execute(Connection connection) throws SQLException {
                DatabaseMetaData dbm = connection.getMetaData();
                ResultSet cpe_tab = dbm.getTables(connection.getCatalog(), "mitre", "cpe", null);
                if (cpe_tab.next()) {
                    db_exists = true;
                    ResultSet cwe_tab = dbm.getTables(connection.getCatalog(), "mitre", "cwe", null);
                    if (cwe_tab.next()) {
                        db_extended = true;
                    }
                }
            }
        });

        // Closing session and session factory
        control_sess.close();
        control_sf.close();

        // Creating configuration, session factory and session
        Configuration con = getConfiguration(config_file);
        ServiceRegistry reg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build();
        SessionFactory sf = con.buildSessionFactory(reg);
        Session session = sf.openSession();

        // If the database structure is extended, following code will be executed
        if (db_exists && db_extended) {
            // Beginning transaction
            Transaction txv = session.beginTransaction();
            // Ensuring optimalization
            int refresh = 0;
            System.out.println("Extended structure of the database detected, actualization of CVE and CPE data started");
            // Writing console info into file
            PrintStream default_out = System.out;
            PrintStream new_out = null;
            try {
                new_out = new PrintStream("exclude/update_console.txt");
            }
            catch (Exception e) {
                e.printStackTrace();
            }
            if (new_out != null) System.setOut(new_out);
            // Parsing CVE and CPE data from input file
            List<extended_mitre.cve.CVEobject> cve_objs = extended_mitre.cve.CVEobject.CVEjsonToObjects(update_file, null);
            // List for removing objects that will be updated now later on
            List<extended_mitre.cve.CVEobject> cves_to_remove = new ArrayList<>();
            for (extended_mitre.cve.CVEobject cve_obj : cve_objs) {
                // Getting specific CVE from the database
                extended_mitre.cve.CVEobject cve_db = session.get(extended_mitre.cve.CVEobject.class, cve_obj.getMeta_data_id());
                if (cve_db != null) {
                    refresh++;
                    // Ensuring optimalization
                    if (refresh % 150 == 0) {
                        txv.commit();
                        session.close();
                        session = sf.openSession();
                        txv = session.beginTransaction();
                    }

                    // Removing object that was updated now
                    cves_to_remove.add(cve_obj);

                    // Quickly updating CVE and CPE objects in the database
                    extended_mitre.cve.CVEobject.quickUpdateCore(session, cve_db, cve_obj);
                }
            }
            // Committing transaction, closing session
            if (txv.isActive()) txv.commit();
            if (session.isOpen()) session.close();
            // Removing all objects, that has been updated until now
            cve_objs.removeAll(cves_to_remove);
            // Putting all new CVE objects into database
            extended_mitre.cve.CVEobject.putIntoDatabaseCore(cve_objs, sf);
            // Turning console in IDE back on
            System.setOut(default_out);
            System.out.println("Quick actualization of CVE and CPE data done \nPreparing file with valuable SQL queries");
            // Filtering query output file for getting only the valuable SQL queries
            filterUpdateQueryFile(output_file);
            System.out.println("Preparation of file with valuable SQL queries done");
            db_exists = false;
            db_extended = false;
        }

        // If the database structure is basic, following code will be executed
        else if (db_exists) {
            // Beginning transaction
            Transaction txv = session.beginTransaction();
            // Ensuring optimalization
            int refresh = 0;
            System.out.println("Basic structure of the database detected, actualization of CVE and CPE data started");
            // Writing console info into file
            PrintStream default_out = System.out;
            PrintStream new_out = null;
            try {
                new_out = new PrintStream("exclude/update_console.txt");
            }
            catch (Exception e) {
                e.printStackTrace();
            }
            if (new_out != null) System.setOut(new_out);
            // Parsing CVE and CPE data from input file
            List<basic_mitre.cve.CVEobject> cve_objs = basic_mitre.cve.CVEobject.CVEjsonToObjects(update_file);
            // List for removing objects that will be updated now later on
            List<basic_mitre.cve.CVEobject> cves_to_remove = new ArrayList<>();
            for (basic_mitre.cve.CVEobject cve_obj : cve_objs) {
                // Getting specific CVE from the database
                basic_mitre.cve.CVEobject cve_db = session.get(basic_mitre.cve.CVEobject.class, cve_obj.getMeta_data_id());
                if (cve_db != null) {
                    refresh++;
                    // Ensuring optimalization
                    if (refresh % 150 == 0) {
                        txv.commit();
                        session.close();
                        session = sf.openSession();
                        txv = session.beginTransaction();
                    }

                    // Removing object that was updated now
                    cves_to_remove.add(cve_obj);

                    // Quickly updating CVE and CPE objects in the database
                    basic_mitre.cve.CVEobject.quickUpdateCore(session, cve_db, cve_obj);
                }
            }
            // Committing transaction, closing session
            if (txv.isActive()) txv.commit();
            if (session.isOpen()) session.close();
            // Removing all objects, that has been updated until now
            cve_objs.removeAll(cves_to_remove);
            // Putting all new CVE objects into database
            basic_mitre.cve.CVEobject.putIntoDatabaseCore(cve_objs, sf);
            // Turning console in IDE on again
            System.setOut(default_out);
            System.out.println("Quick actualization of CVE and CPE data done \nPreparing file with valuable SQL queries");
            // Filtering query output file for getting only the valuable SQL queries
            filterUpdateQueryFile(output_file);
            System.out.println("Preparation of file with valuable SQL queries done");
            db_exists = false;
        }

        // If the database doesn't contain any table, nothing will happen
        else System.out.println("Database structure doesn't exist, it needs to be filled first, nothing will happen now");

        // Closing session factory
        sf.close();
    }

    /**
     * This method's purpose is to put all given CVE and CPE objects and related objects into database
     * It uses the basicDBcore() method for this purpose
     *
     * @param cpe_file   path to .json file with CPE dictionary data (CPE match feed file)
     * @param cve_files  paths to .json files with CVE objects
     */
    public static void basicDatabase(String cpe_file, String[] cve_files) {
        System.out.println("Basic database creation started");

        // Creating configuration
        db_exists = true;
        Configuration con = getConfiguration(null);
        db_exists = false;
        ServiceRegistry reg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build();
        // Creating session, session factory and transaction
        SessionFactory sf = con.buildSessionFactory(reg);
        Session session = sf.openSession();

        Query q = session.createQuery("from cpe");
        q.setMaxResults(10);
        // If the cpe table is empty, the method doesn't empty the database
        if (q.getResultList().isEmpty()) {
            System.out.println("Database empty, emptying is not included");
            // Closing session
            session.close();
            // Putting all CVE and CPE data into database along with all relations
            basicDBcore(cpe_file, cve_files, sf);
        }

        // If the cpe table isn't empty, the method does empty the database
        else {
            System.out.println("Database is not empty, emptying database");
            // Closing session
            session.close();
            // Emptying database
            flushDB(sf);
            System.out.println("Emptying done");
            // Closing and building session factory to create structure of the database again
            sf.close();
            reg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build();
            sf = con.buildSessionFactory(reg);
            // Putting all CVE and CPE data into database along with all relations
            basicDBcore(cpe_file, cve_files, sf);
        }
        // Closing session factory
        sf.close();
        System.out.println("Basic database creation done");
    }

    /**
     * This method's purpose is to put all given CVE, CWE and CAPEC objects and related objects into database
     * It uses the extendedDBcore() method for this purpose
     *
     * @param cpe_file path to .json file with CPE dictionary data (CPE match feed file)
     * @param cve_files paths to .json files with CVE objects
     * @param cwe_file path to .xml file with CWE data
     * @param capec_file path to .xml file with CAPEC data
     */
    public static void extendedDatabase(String cpe_file, String[] cve_files, String cwe_file, String capec_file) {
        List<extended_mitre.cwe.CWEextRefObj> external_refs = extended_mitre.cwe.CWEextRefObj.CWEextRefToArrayList(cwe_file); // Getting External Reference objects from the first file
        external_refs.addAll(extended_mitre.cwe.CWEextRefObj.CWEextRefToArrayList(capec_file)); // Getting External Reference objects from the second file
        List<extended_mitre.capec.CAPECobject> capec_objs = extended_mitre.capec.CAPECobject.CAPECfileToArrayList(capec_file, external_refs); // Getting CAPEC objects from file
        List<extended_mitre.cwe.CWEobject> cwe_objs = extended_mitre.cwe.CWEobject.CWEfileToArraylist(cwe_file, capec_objs, external_refs); // Getting CWE objects from file

        System.out.println("Extended database creation started");

        // Creating configuration, session factory and session
        db_extended = true;
        Configuration con = getConfiguration(null);
        db_extended = false;
        ServiceRegistry reg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build();
        SessionFactory sf = con.buildSessionFactory(reg);
        Session session = sf.openSession();

        Query q = session.createQuery("from cpe_ex");
        q.setMaxResults(10);
        // If the cpe table is empty, the method doesn't empty the database
        if (q.getResultList().isEmpty()) {
            System.out.println("Database empty, emptying is not included");
            // Closing session
            session.close();
            // Putting all CVE, CPE, CAPEC and CWE data into database along with all relations
            extendedDBcore(cpe_file, cve_files, cwe_objs, capec_objs, external_refs, sf);
        }
        // If the cpe table isn't empty, the method does empty the database
        else {
            System.out.println("Database is not empty, emptying database");
            // Closing session
            session.close();
            // Emptying database
            flushDB(sf);
            System.out.println("Emptying done");
            // Closing and building session factory to create structure of the database again
            sf.close();
            reg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build();
            sf = con.buildSessionFactory(reg);
            // Putting all CVE, CPE, CAPEC and CWE data into database along with all relations
            extendedDBcore(cpe_file, cve_files, cwe_objs, capec_objs, external_refs, sf);
        }
        // Closing session factory
        sf.close();
        System.out.println("Extended database creation done");
    }

    /**
     * This method's purpose is to put all given CVE and CPE objects and related objects into database
     *
     * @param cpe_file   path to .json file with CPE data (CPE match feed file)
     * @param cve_files  paths to .json files with CVE objects
     * @param sf         object needed to get hibernate Session Factory and to work with database
     */
    public static void basicDBcore(String cpe_file, String[] cve_files, SessionFactory sf) {
        // Putting CPE objects from CPE match feed file into database
        basic_mitre.cpe.CPEobject.putIntoDatabase(cpe_file, sf); // file - https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip

        // Putting CVE objects into database
        basic_mitre.cve.CVEobject.putIntoDatabase(cve_files, sf);
    }

    /**
     * This method's purpose is to put all given CVE, CWE and CAPEC objects and related objects into database
     *
     * @param cpe_file        path to .json file with CPE data (CPE match feed file)
     * @param cve_files       paths to .json files with CVE objects
     * @param cwe_objs        List of parsed CWE objects
     * @param capec_objs      List of parsed CAPEC objects
     * @param external_refs   List of parsed External Reference objects
     * @param sf              object needed to get hibernate Session Factory and to work with database
     */
    public static void extendedDBcore(String cpe_file, String[] cve_files, List<extended_mitre.cwe.CWEobject> cwe_objs, List<extended_mitre.capec.CAPECobject> capec_objs, List<extended_mitre.cwe.CWEextRefObj> external_refs, SessionFactory sf) {
        // Putting CPE objects from CPE match feed file into database
        extended_mitre.cpe.CPEobject.putIntoDatabase(cpe_file, sf); // file - https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip

        System.out.println("Filling database with CVE, CWE and CAPEC objects started");
        // Creating session, beginning transaction
        Session sessionc = sf.openSession();
        Transaction txv = sessionc.beginTransaction();

        // Putting External Reference objects into database
        for (extended_mitre.cwe.CWEextRefObj ext_ref : external_refs) {
            sessionc.save(ext_ref);
        }

        // Committing transaction, closing session and session factory
        txv.commit();
        sessionc.close();

        // Putting CAPEC objects into database
        extended_mitre.capec.CAPECobject.CAPECintoDatabase(capec_objs, sf);

        // Putting CWE objects into database
        extended_mitre.cwe.CWEobject.CWEintoDatabase(cwe_objs, sf);

        // Putting CVE objects into database
        extended_mitre.cve.CVEobject.putIntoDatabase(cve_files, cwe_objs, sf);
    }

    /**
     * This method's purpose is to empty the database
     *
     * @param sf              object needed to get hibernate Session Factory and to work with database
     */
    public static void flushDB(SessionFactory sf) {
        // Openning session
        Session session = sf.openSession();
        // Emptying database
        session.beginTransaction();
        session.createSQLQuery("DROP TABLE IF EXISTS mitre.alternate_term CASCADE;" +
                "DROP TABLE IF EXISTS mitre.att_step_techniques CASCADE;" +
                "DROP TABLE IF EXISTS mitre.capec CASCADE;" +
                "DROP TABLE IF EXISTS mitre.capec_attack_step CASCADE;" +
                "DROP TABLE IF EXISTS mitre.capec_examples CASCADE;" +
                "DROP TABLE IF EXISTS mitre.capec_indicators CASCADE;" +
                "DROP TABLE IF EXISTS mitre.capec_mitigations CASCADE;" +
                "DROP TABLE IF EXISTS mitre.capec_prerequisites CASCADE;" +
                "DROP TABLE IF EXISTS mitre.capec_resources CASCADE;" +
                "DROP TABLE IF EXISTS mitre.capec_skill CASCADE;" +
                "DROP TABLE IF EXISTS mitre.compl_cpe CASCADE;" +
                "DROP TABLE IF EXISTS mitre.conseq_impacts CASCADE;" +
                "DROP TABLE IF EXISTS mitre.conseq_likelihoods CASCADE;" +
                "DROP TABLE IF EXISTS mitre.conseq_notes CASCADE;" +
                "DROP TABLE IF EXISTS mitre.conseq_scopes CASCADE;" +
                "DROP TABLE IF EXISTS mitre.consequence CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cpe CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cpe_compl_cpe CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cve CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cve_cwe CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cve_descriptions CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cve_node CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cve_node_cpe CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cve_reference CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cvss2 CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cvss3 CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cwe CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cwe_affected_resources CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cwe_applicable_platform CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cwe_bg_details CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cwe_capec CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cwe_detection_method CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cwe_functional_areas CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cwe_introduction CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cwe_observed_example CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cwe_potential_mitigation CASCADE;" +
                "DROP TABLE IF EXISTS mitre.cwe_weakness_ordinality CASCADE;" +
                "DROP TABLE IF EXISTS mitre.dem_ex_body_texts CASCADE;" +
                "DROP TABLE IF EXISTS mitre.dem_ex_example_code CASCADE;" +
                "DROP TABLE IF EXISTS mitre.demonstrative_examp CASCADE;" +
                "DROP TABLE IF EXISTS mitre.ext_ref_authors CASCADE;" +
                "DROP TABLE IF EXISTS mitre.external_ref_ref CASCADE;" +
                "DROP TABLE IF EXISTS mitre.external_reference CASCADE;" +
                "DROP TABLE IF EXISTS mitre.note CASCADE;" +
                "DROP TABLE IF EXISTS mitre.pot_mit_phases CASCADE;" +
                "DROP TABLE IF EXISTS mitre.ref_tags CASCADE;" +
                "DROP TABLE IF EXISTS mitre.rel_capec_exclude_ids CASCADE;" +
                "DROP TABLE IF EXISTS mitre.related_attack_pattern CASCADE;" +
                "DROP TABLE IF EXISTS mitre.related_weakness CASCADE;" +
                "DROP TABLE IF EXISTS mitre.taxonomy_mapping CASCADE;").executeUpdate();
        session.getTransaction().commit();
        // Closing session
        session.close();
    }

    /**
     * This method's purpose is to create and return Configuration object with either basic or extended database structure
     *
     * @param config_file path to file with Hibernate configuration data if the default isn't used
     * @return Configuration object with current database structure
     */
    public static Configuration getConfiguration (String config_file) {
        Configuration con = null;

        if (config_file != null && db_extended) {
            // extended structure of the database
            con = new Configuration().configure(config_file).addAnnotatedClass(extended_mitre.cve.CVEobject.class).addAnnotatedClass(extended_mitre.cpe.CPEobject.class)
                    .addAnnotatedClass(extended_mitre.cvss.CVSS2object.class).addAnnotatedClass(extended_mitre.cvss.CVSS3object.class).addAnnotatedClass(extended_mitre.cpe.CPEnodeObject.class)
                    .addAnnotatedClass(extended_mitre.cve.ReferenceObject.class).addAnnotatedClass(extended_mitre.cpe.CPEcomplexObj.class).addAnnotatedClass(extended_mitre.cpe.CPEnodeToCPE.class)
                    .addAnnotatedClass(extended_mitre.capec.CAPECattStepObj.class).addAnnotatedClass(extended_mitre.capec.CAPECobject.class).addAnnotatedClass(extended_mitre.capec.CAPECrelationObj.class)
                    .addAnnotatedClass(extended_mitre.capec.CAPECskillObj.class).addAnnotatedClass(extended_mitre.cwe.CWEalterTermObj.class).addAnnotatedClass(extended_mitre.cwe.CWEapplPlatfObj.class)
                    .addAnnotatedClass(extended_mitre.cwe.CWEconseqObj.class).addAnnotatedClass(extended_mitre.cwe.CWEdemExObj.class).addAnnotatedClass(extended_mitre.cwe.CWEdetMethObj.class)
                    .addAnnotatedClass(extended_mitre.cwe.CWEexampCodeObj.class).addAnnotatedClass(extended_mitre.cwe.CWEextRefRefObj.class).addAnnotatedClass(extended_mitre.cwe.CWEintrModesObj.class)
                    .addAnnotatedClass(extended_mitre.cwe.CWEnoteObj.class).addAnnotatedClass(extended_mitre.cwe.CWEobject.class).addAnnotatedClass(extended_mitre.cwe.CWEobsExObj.class)
                    .addAnnotatedClass(extended_mitre.cwe.CWEpotMitObj.class).addAnnotatedClass(extended_mitre.cwe.CWErelationObj.class).addAnnotatedClass(extended_mitre.cwe.CWEtaxMapObj.class)
                    .addAnnotatedClass(extended_mitre.cwe.CWEweakOrdObj.class).addAnnotatedClass(extended_mitre.cwe.CWEextRefObj.class);
        }
        else if (config_file != null && db_exists) {
            // basic structure of the database
            con = new Configuration().configure(config_file).addAnnotatedClass(basic_mitre.cve.CVEobject.class).addAnnotatedClass(basic_mitre.cpe.CPEobject.class)
                    .addAnnotatedClass(basic_mitre.cvss.CVSS2object.class).addAnnotatedClass(basic_mitre.cvss.CVSS3object.class).addAnnotatedClass(basic_mitre.cpe.CPEnodeObject.class)
                    .addAnnotatedClass(basic_mitre.cve.ReferenceObject.class).addAnnotatedClass(basic_mitre.cpe.CPEcomplexObj.class).addAnnotatedClass(basic_mitre.cpe.CPEnodeToCPE.class);
        }
        else if (db_extended) {
            // extended structure of the database
            con = new Configuration().configure().addAnnotatedClass(extended_mitre.cve.CVEobject.class).addAnnotatedClass(extended_mitre.cpe.CPEobject.class)
                    .addAnnotatedClass(extended_mitre.cvss.CVSS2object.class).addAnnotatedClass(extended_mitre.cvss.CVSS3object.class).addAnnotatedClass(extended_mitre.cpe.CPEnodeObject.class)
                    .addAnnotatedClass(extended_mitre.cve.ReferenceObject.class).addAnnotatedClass(extended_mitre.cpe.CPEcomplexObj.class).addAnnotatedClass(extended_mitre.cpe.CPEnodeToCPE.class)
                    .addAnnotatedClass(extended_mitre.capec.CAPECattStepObj.class).addAnnotatedClass(extended_mitre.capec.CAPECobject.class).addAnnotatedClass(extended_mitre.capec.CAPECrelationObj.class)
                    .addAnnotatedClass(extended_mitre.capec.CAPECskillObj.class).addAnnotatedClass(extended_mitre.cwe.CWEalterTermObj.class).addAnnotatedClass(extended_mitre.cwe.CWEapplPlatfObj.class)
                    .addAnnotatedClass(extended_mitre.cwe.CWEconseqObj.class).addAnnotatedClass(extended_mitre.cwe.CWEdemExObj.class).addAnnotatedClass(extended_mitre.cwe.CWEdetMethObj.class)
                    .addAnnotatedClass(extended_mitre.cwe.CWEexampCodeObj.class).addAnnotatedClass(extended_mitre.cwe.CWEextRefRefObj.class).addAnnotatedClass(extended_mitre.cwe.CWEintrModesObj.class)
                    .addAnnotatedClass(extended_mitre.cwe.CWEnoteObj.class).addAnnotatedClass(extended_mitre.cwe.CWEobject.class).addAnnotatedClass(extended_mitre.cwe.CWEobsExObj.class)
                    .addAnnotatedClass(extended_mitre.cwe.CWEpotMitObj.class).addAnnotatedClass(extended_mitre.cwe.CWErelationObj.class).addAnnotatedClass(extended_mitre.cwe.CWEtaxMapObj.class)
                    .addAnnotatedClass(extended_mitre.cwe.CWEweakOrdObj.class).addAnnotatedClass(extended_mitre.cwe.CWEextRefObj.class);
        }
        else if (db_exists) {
            // basic structure of the database
            con = new Configuration().configure().addAnnotatedClass(basic_mitre.cve.CVEobject.class).addAnnotatedClass(basic_mitre.cpe.CPEobject.class)
                    .addAnnotatedClass(basic_mitre.cvss.CVSS2object.class).addAnnotatedClass(basic_mitre.cvss.CVSS3object.class).addAnnotatedClass(basic_mitre.cpe.CPEnodeObject.class)
                    .addAnnotatedClass(basic_mitre.cve.ReferenceObject.class).addAnnotatedClass(basic_mitre.cpe.CPEcomplexObj.class).addAnnotatedClass(basic_mitre.cpe.CPEnodeToCPE.class);
        }

        return con;
    }

    /**
     * This method's purpose is to take file with logged SQL queries from quickUpdate, filter them and put them in
     * right format into a new file (its path will be given in input)
     *
     * @param output_file path to file that will be created and filled with ready SQL queries containing update data
     */
    public static void filterUpdateQueryFile (String output_file) {
        // Creating new ArrayList that will be filled with all SQL queries needed for database update
        List<String> right_sql_queries = new ArrayList<>();
        try {
            // Reading .log file containing all made SQL queries during update
            BufferedReader br = new BufferedReader(new FileReader("exclude/spy.log"));
            // Going through each line of the .log file
            for (String line; (line = br.readLine()) != null;) {

                // Slicing each line into parts
                String[] line_parts = line.split("\\|", -1);

                // Controlling if current line contains valuable SQL query, if it does, it will be added into earlier created ArrayList
                if (line_parts[3].equals("statement")) {
                    if (line_parts[5].startsWith("delete from") || line_parts[5].startsWith("insert into") ||
                            line_parts[5].startsWith("update") || line_parts[5].startsWith("DELETE FROM") ||
                            line_parts[5].startsWith("INSERT INTO") || line_parts[5].startsWith("UPDATE")) {
                        right_sql_queries.add(line_parts[5]+";");
                    }
                }
            }
            // Closing reading of the .log file
            br.close();
            // Writing all valuable queries into given output_file
            BufferedWriter file_write = new BufferedWriter(new FileWriter(output_file));
            for (String query : right_sql_queries) {
                file_write.write(query+"\n");
            }
            // Closing writing into the given output file
            file_write.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
