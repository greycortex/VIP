package mitre;

import mitre.capec.CAPECattStepObj;
import mitre.capec.CAPECobject;
import mitre.capec.CAPECrelationObj;
import mitre.capec.CAPECskillObj;
import mitre.cpe.CPEcomplexObj;
import mitre.cpe.CPEnodeObject;
import mitre.cpe.CPEnodeToComplex;
import mitre.cpe.CPEobject;
import mitre.cve.CVEobject;
import mitre.cve.ReferenceObject;
import mitre.cvss.CVSS2object;
import mitre.cvss.CVSS3object;
import mitre.cwe.*;
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
     * This method's purpose is to put all given CVE, CWE and CAPEC objects and related objects into database
     * It uses the extendedDBcore() method for this purpose
     *
     * @param cpe_file path to .json file with CPE dictionary data (CPE match feed file)
     * @param cve_files paths to .json files with CVE objects
     * @param cwe_file path to .xml file with CWE data
     * @param capec_file path to .xml file with CAPEC data
     */
    public static void extendedDatabase(String cpe_file, String[] cve_files, String cwe_file, String capec_file) {
        List<CWEextRefObj> external_refs = CWEextRefObj.CWEextRefToArrayList(cwe_file); // Getting External Reference objects from the first file
        external_refs.addAll(CWEextRefObj.CWEextRefToArrayList(capec_file)); // Getting External Reference objects from the second file
        List<CAPECobject> capec_objs = CAPECobject.CAPECfileToArrayList(capec_file, external_refs); // Getting CAPEC objects from file
        List<CWEobject> cwe_objs = CWEobject.CWEfileToArraylist(cwe_file, capec_objs, external_refs); // Getting CWE objects from file

        System.out.println("Extended database creation started");

        // Creating configuration, session factory and session
        Configuration con = new Configuration().configure().addAnnotatedClass(CVEobject.class).addAnnotatedClass(CPEobject.class)
                .addAnnotatedClass(CVSS2object.class).addAnnotatedClass(CVSS3object.class).addAnnotatedClass(CPEnodeObject.class)
                .addAnnotatedClass(ReferenceObject.class).addAnnotatedClass(CPEcomplexObj.class).addAnnotatedClass(CPEnodeToComplex.class)
                .addAnnotatedClass(CAPECattStepObj.class).addAnnotatedClass(CAPECobject.class).addAnnotatedClass(CAPECrelationObj.class)
                .addAnnotatedClass(CAPECskillObj.class).addAnnotatedClass(CWEalterTermObj.class).addAnnotatedClass(CWEapplPlatfObj.class)
                .addAnnotatedClass(CWEconseqObj.class).addAnnotatedClass(CWEdemExObj.class).addAnnotatedClass(CWEdetMethObj.class)
                .addAnnotatedClass(CWEexampCodeObj.class).addAnnotatedClass(CWEextRefRefObj.class).addAnnotatedClass(CWEintrModesObj.class)
                .addAnnotatedClass(CWEnoteObj.class).addAnnotatedClass(CWEobject.class).addAnnotatedClass(CWEobsExObj.class)
                .addAnnotatedClass(CWEpotMitObj.class).addAnnotatedClass(CWErelationObj.class).addAnnotatedClass(CWEtaxMapObj.class)
                .addAnnotatedClass(CWEweakOrdObj.class).addAnnotatedClass(CWEextRefObj.class);
        ServiceRegistry reg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build();
        SessionFactory sf = con.buildSessionFactory(reg);

        Session session = sf.openSession();

        Query q = session.createQuery("from cpe");
        q.setMaxResults(10);
        // If the cpe table is empty, the method doesn't empty the database
        if (q.getResultList().isEmpty()) {
            System.out.println("Database table empty, emptying is not included");
            // Closing session
            session.close();
            // Putting all CVE, CPE, CAPEC and CWE data into database along with all relations
            extendedDBcore(cpe_file, cve_files, cwe_objs, capec_objs, external_refs, sf);
        }
        // If the cpe table isn't empty, the method does empty the database
        else {
            System.out.println("Database table not empty, emptying database");
            // Emptying database
            session.beginTransaction();
            session.createSQLQuery("DROP TABLE IF EXISTS mitre.cpe_compl_cpe CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cpe CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cve_node CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cve_node_compl_cpe CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cve CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cve_descriptions CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cvss2 CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cvss3 CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cve_reference CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.ref_tags CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_affected_resources CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.alternate_term CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_applicable_platform CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.capec_attack_step CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_bg_details CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.dem_ex_body_texts CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.capec CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.related_attack_pattern CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.consequence CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_capec CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.related_weakness CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.demonstrative_examp CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_detection_method CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.capec_examples CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.dem_ex_example_code CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.rel_capec_exclude_ids CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.external_ref_ref CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_functional_areas CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.conseq_impacts CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.capec_indicators CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_introduction CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.conseq_likelihoods CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.capec_mitigations CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.note CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_observed_example CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.pot_mit_phases CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_potential_mitigation CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.capec_prerequisites CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.conseq_scopes CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.capec_skill CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.capec_resources CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.taxonomy_mapping CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.att_step_techniques CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cwe_weakness_ordinality CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.conseq_notes CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.cve_cwe CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.external_reference CASCADE;" +
                    "DROP TABLE IF EXISTS mitre.ext_ref_authors CASCADE;").executeUpdate();
            session.getTransaction().commit();
            // Closing session
            session.close();
            // Putting all CVE, CPE, CAPEC and CWE data into database along with all relations
            extendedDBcore(cpe_file, cve_files, cwe_objs, capec_objs, external_refs, sf);
        }
        // Closing session factory
        sf.close();
        System.out.println("Extended database creation done");
    }

    /**
     * This method's purpose is to quickly update CVE and CPE objects in the database
     *
     * @param fileName path to .json file with CVE objects - "modified" file containing recently changed data
     */
    public static void quickUpdate(String fileName) {
        System.out.println("Actualization of CPE and CVE objects in the database started");
        // Creating configuration
        Configuration con = new Configuration().configure().addAnnotatedClass(CVEobject.class).addAnnotatedClass(CPEobject.class)
                .addAnnotatedClass(CVSS2object.class).addAnnotatedClass(CVSS3object.class).addAnnotatedClass(CPEnodeObject.class)
                .addAnnotatedClass(ReferenceObject.class).addAnnotatedClass(CPEcomplexObj.class).addAnnotatedClass(CPEnodeToComplex.class);
        ServiceRegistry reg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build();
        // Creating session, session factory and transaction
        SessionFactory sf = con.buildSessionFactory(reg);
        Session session = sf.openSession();
        Transaction txv = session.beginTransaction();

        // Taking objects returned by the CVEjsonToObjects() method from "modified" file
        List<CVEobject> cve_objs = CVEobject.CVEjsonToObjects(fileName, null);
        System.out.println("CVE objects from the 'modified' file parsed");

        // Ensuring optimalization
        int refresh = 0;
        // Deleting all existing but not up-to-date CVE objects from database
        for (CVEobject cve : cve_objs) {
            refresh++;
            // Ensuring optimalization
            if (refresh % 250 == 0) {
                txv.commit();
                session.close();
                session = sf.openSession();
                txv = session.beginTransaction();
            }
            CVEobject cve_from_db = session.get(CVEobject.class, cve.getMeta_data_id());
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
        CVEobject.putIntoDatabase(file_arr, null, sf);

        // Closing session factory
        sf.close();
        System.out.println("Actualization of CPE and CVE objects in the database done");
    }

    /**
     * This method's purpose is to put all given CVE, CWE and CAPEC objects and related objects into database
     *
     * @param cpe_file        paths to .json file with CPE data (CPE match feed file)
     * @param cve_files       paths to .json files with CVE objects
     * @param cwe_objs        List of parsed CWE objects
     * @param capec_objs      List of parsed CAPEC objects
     * @param external_refs   List of parsed External Reference objects
     * @param sf              object needed to get hibernate Session Factory and to work with database
     */
    public static void extendedDBcore(String cpe_file, String[] cve_files, List<CWEobject> cwe_objs, List<CAPECobject> capec_objs, List<CWEextRefObj> external_refs, SessionFactory sf) {
        // Putting CPE objects from CPE match feed file into database
        CPEobject.putIntoDatabase(cpe_file, sf); // file - https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip

        System.out.println("Filling database with CVE, CWE and CAPEC objects started");
        // Creating session, beginning transaction
        Session sessionc = sf.openSession();
        Transaction txv = sessionc.beginTransaction();

        // Putting External Reference objects into database
        for (CWEextRefObj ext_ref : external_refs) {
            sessionc.save(ext_ref);
        }

        // Committing transaction, closing session and session factory
        txv.commit();
        sessionc.close();

        // Putting CAPEC objects into database
        CAPECobject.CAPECintoDatabase(capec_objs, sf);

        // Putting CWE objects into database
        CWEobject.CWEintoDatabase(cwe_objs, sf);

        // Putting CVE objects into database
        CVEobject.putIntoDatabase(cve_files, cwe_objs, sf);
    }
}
