import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.service.ServiceRegistry;

import javax.persistence.Query;
import java.util.List;

/**
 * This class' purpose is to connect all methods that put various objects into database so that the needed operation will be executed
 *
 * @author Tomas Bozek (XarfNao)
 */
public class NVDobject {

    /**
     * This method's purpose is to quickly update CVE and CPE objects in the database
     *
     * @param fileName path to .json file with CVE objects - "modified" file containing recently changed data
     */
    public static void quickUpdate(String fileName) {
        System.out.println("Actualization of CPE and CVE objects in the database started");
        // Creating configuration
        Configuration con = new Configuration().configure().addAnnotatedClass(basic_mitre.cve.CVEobject.class).addAnnotatedClass(basic_mitre.cpe.CPEobject.class)
                .addAnnotatedClass(basic_mitre.cvss.CVSS2object.class).addAnnotatedClass(basic_mitre.cvss.CVSS3object.class).addAnnotatedClass(basic_mitre.cpe.CPEnodeObject.class)
                .addAnnotatedClass(basic_mitre.cve.ReferenceObject.class).addAnnotatedClass(basic_mitre.cpe.CPEcomplexObj.class).addAnnotatedClass(basic_mitre.cpe.CPEnodeToCPE.class);
        ServiceRegistry reg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build(); // basic structure of the database
        // Creating session, session factory and transaction
        SessionFactory sf = con.buildSessionFactory(reg);
        Session session = sf.openSession();
        Transaction txv = session.beginTransaction();

        // Taking objects returned by the CVEjsonToObjects() method from "modified" file
        List<basic_mitre.cve.CVEobject> cve_objs = basic_mitre.cve.CVEobject.CVEjsonToObjects(fileName);
        System.out.println("CVE objects from the 'modified' file parsed");

        // Ensuring optimalization
        int refresh = 0;
        // Deleting all existing but not up-to-date CVE objects from database
        for (basic_mitre.cve.CVEobject cve : cve_objs) {
            refresh++;
            // Ensuring optimalization
            if (refresh % 250 == 0) {
                txv.commit();
                session.close();
                session = sf.openSession();
                txv = session.beginTransaction();
            }
            basic_mitre.cve.CVEobject cve_from_db = session.get(basic_mitre.cve.CVEobject.class, cve.getMeta_data_id());
            if (cve_from_db != null) {
                session.delete(cve_from_db);
            }
        }
        System.out.println("Existing but not up-to-date CVE data removed from the database");
        // Commiting transaction, closing session
        txv.commit();
        session.close();

        // Putting all new and up-to-date CVE objects into database
        String[] file_arr = {fileName};
        basic_mitre.cve.CVEobject.putIntoDatabase(file_arr, sf);

        // Closing session factory
        sf.close();
        System.out.println("Actualization of CPE and CVE objects in the database done");
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
        Configuration con = new Configuration().configure().addAnnotatedClass(basic_mitre.cve.CVEobject.class).addAnnotatedClass(basic_mitre.cpe.CPEobject.class)
                .addAnnotatedClass(basic_mitre.cvss.CVSS2object.class).addAnnotatedClass(basic_mitre.cvss.CVSS3object.class).addAnnotatedClass(basic_mitre.cpe.CPEnodeObject.class)
                .addAnnotatedClass(basic_mitre.cve.ReferenceObject.class).addAnnotatedClass(basic_mitre.cpe.CPEcomplexObj.class).addAnnotatedClass(basic_mitre.cpe.CPEnodeToCPE.class);
        ServiceRegistry reg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build(); // basic structure of the database
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
        Configuration con = new Configuration().configure().addAnnotatedClass(extended_mitre.cve.CVEobject.class).addAnnotatedClass(extended_mitre.cpe.CPEobject.class)
                .addAnnotatedClass(extended_mitre.cvss.CVSS2object.class).addAnnotatedClass(extended_mitre.cvss.CVSS3object.class).addAnnotatedClass(extended_mitre.cpe.CPEnodeObject.class)
                .addAnnotatedClass(extended_mitre.cve.ReferenceObject.class).addAnnotatedClass(extended_mitre.cpe.CPEcomplexObj.class).addAnnotatedClass(extended_mitre.cpe.CPEnodeToCPE.class)
                .addAnnotatedClass(extended_mitre.capec.CAPECattStepObj.class).addAnnotatedClass(extended_mitre.capec.CAPECobject.class).addAnnotatedClass(extended_mitre.capec.CAPECrelationObj.class)
                .addAnnotatedClass(extended_mitre.capec.CAPECskillObj.class).addAnnotatedClass(extended_mitre.cwe.CWEalterTermObj.class).addAnnotatedClass(extended_mitre.cwe.CWEapplPlatfObj.class)
                .addAnnotatedClass(extended_mitre.cwe.CWEconseqObj.class).addAnnotatedClass(extended_mitre.cwe.CWEdemExObj.class).addAnnotatedClass(extended_mitre.cwe.CWEdetMethObj.class)
                .addAnnotatedClass(extended_mitre.cwe.CWEexampCodeObj.class).addAnnotatedClass(extended_mitre.cwe.CWEextRefRefObj.class).addAnnotatedClass(extended_mitre.cwe.CWEintrModesObj.class)
                .addAnnotatedClass(extended_mitre.cwe.CWEnoteObj.class).addAnnotatedClass(extended_mitre.cwe.CWEobject.class).addAnnotatedClass(extended_mitre.cwe.CWEobsExObj.class)
                .addAnnotatedClass(extended_mitre.cwe.CWEpotMitObj.class).addAnnotatedClass(extended_mitre.cwe.CWErelationObj.class).addAnnotatedClass(extended_mitre.cwe.CWEtaxMapObj.class)
                .addAnnotatedClass(extended_mitre.cwe.CWEweakOrdObj.class).addAnnotatedClass(extended_mitre.cwe.CWEextRefObj.class); // extended structure of the database
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
}
