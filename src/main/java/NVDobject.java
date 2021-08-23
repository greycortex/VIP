import basic_mitre.cpe.CPEcomplexObj;
import basic_mitre.cpe.CPEnodeObject;
import basic_mitre.cpe.CPEnodeToCPE;
import basic_mitre.cpe.CPEobject;
import basic_mitre.cve.ReferenceObject;
import extended_mitre.cwe.CWEobject;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.jdbc.Work;
import org.hibernate.service.ServiceRegistry;

import javax.persistence.Query;
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
     *
     * @param update_file path to .json file with CVE objects - "modified" file containing recently changed data
     */
    public static void quickUpdate(String update_file) {
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

        // If the database structure is extended, following code will be executed
        if (db_exists && db_extended) {
            // Creating configuration, session factory, session and transaction
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
            Transaction txv = session.beginTransaction();
            // Ensuring optimalization
            int refresh = 0;
            System.out.println("Extended structure of the database detected, actualization of CVE and CPE data started");
            // Parsing CVE and CPE data from input file
            List<extended_mitre.cve.CVEobject> cve_objs = extended_mitre.cve.CVEobject.CVEjsonToObjects(update_file, null);
            // List for removing objects that will be updated now later on
            List<extended_mitre.cve.CVEobject> cves_to_remove = new ArrayList<>();
            for (extended_mitre.cve.CVEobject cve_obj : cve_objs) {
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

                    // ---

                    // Removing object that was updated now
                    cves_to_remove.add(cve_obj);
                }
            }
            // Removing all objects, that has been updated until now
            cve_objs.removeAll(cves_to_remove);
            // If the CVE object is new, it is put into the database
            for (extended_mitre.cve.CVEobject obj : cve_objs) {
                refresh++;
                // Putting CVSS v2 object into database
                if (obj.getCvss_v2() != null) session.save(obj.getCvss_v2());
                // Putting CVSS v3 object into database
                if (obj.getCvss_v3() != null) session.save(obj.getCvss_v3());
                // Putting CVE object into database
                session.save(obj);
                // Putting CPE node objects into database
                for (extended_mitre.cpe.CPEnodeObject node_obj : obj.getCpe_nodes()) {
                    if (node_obj != null && node_obj.getComplex_cpe_objs() != null) {
                        // Putting CPE node object into database
                        node_obj.setCve_obj(obj);
                        session.save(node_obj);
                        for (extended_mitre.cpe.CPEcomplexObj complex_cpe_obj : node_obj.getComplex_cpe_objs()) {
                            if (complex_cpe_obj != null) {
                                // Making basic CPE id for creating or getting CPE object later on
                                String basic_cpe_id = complex_cpe_obj.getCpe_id();
                                // ensuring unique ID of complex CPE object
                                if (complex_cpe_obj.getVersion_start_including() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#star_in_" + complex_cpe_obj.getVersion_start_including());
                                }
                                if (complex_cpe_obj.getVersion_start_excluding() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#star_ex_" + complex_cpe_obj.getVersion_start_excluding());
                                }
                                if (complex_cpe_obj.getVersion_end_including() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#end_in_" + complex_cpe_obj.getVersion_end_including());
                                }
                                if (complex_cpe_obj.getVersion_end_excluding() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#end_ex_" + complex_cpe_obj.getVersion_end_excluding());
                                }

                                extended_mitre.cpe.CPEcomplexObj compl_cpe_db = null;
                                extended_mitre.cpe.CPEobject cpe_db = null;
                                // Figuring out if it will be complex or basic CPE object - following is the complex CPE case
                                if (complex_cpe_obj.getVersion_end_excluding() != null || complex_cpe_obj.getVersion_start_excluding() != null ||
                                        complex_cpe_obj.getVersion_end_including() != null || complex_cpe_obj.getVersion_start_including() != null) {
                                    compl_cpe_db = (extended_mitre.cpe.CPEcomplexObj) session.get(extended_mitre.cpe.CPEcomplexObj.class, complex_cpe_obj.getCpe_id());
                                    // Making connection if the complex CPE object already exists
                                    if (compl_cpe_db != null) {
                                        if (session.get(extended_mitre.cpe.CPEnodeToCPE.class, (obj.getMeta_data_id() + "#" + compl_cpe_db.getCpe_id() + "#" + node_obj.getId())) == null) {
                                            // Creating connection between CPE and CVE
                                            extended_mitre.cpe.CPEnodeToCPE node_to_cpe = new extended_mitre.cpe.CPEnodeToCPE((obj.getMeta_data_id() + "#" + compl_cpe_db.getCpe_id() + "#" + node_obj.getId()), compl_cpe_db, node_obj, obj.getMeta_data_id(), complex_cpe_obj.getVulnerable(), null);
                                            // Putting CPE node to CPE object into database
                                            session.save(node_to_cpe);
                                        }
                                    }
                                    // Creating new complex CPE object if it doesn't exist
                                    else {
                                        // Creating basic CPE object to connect with if it doesn't exist
                                        cpe_db = (extended_mitre.cpe.CPEobject) session.get(extended_mitre.cpe.CPEobject.class, basic_cpe_id);
                                        if (cpe_db == null) {
                                            cpe_db = extended_mitre.cpe.CPEobject.cpeUriToObject(basic_cpe_id);
                                            session.save(cpe_db);
                                        }
                                        complex_cpe_obj.setCpe_objs(new ArrayList<>());
                                        // Making connection between complex CPE object and basic CPE object
                                        complex_cpe_obj.getCpe_objs().add(cpe_db);
                                        // Ensuring unique ID and putting complex CPE object into database
                                        complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id()+"#"+obj.getMeta_data_id());
                                        session.save(complex_cpe_obj);
                                        // Making connection between complex CPE object and CVE object
                                        extended_mitre.cpe.CPEnodeToCPE node_to_cpe = new extended_mitre.cpe.CPEnodeToCPE((obj.getMeta_data_id()+"#"+complex_cpe_obj.getCpe_id()+"#"+node_obj.getId()), complex_cpe_obj, node_obj, obj.getMeta_data_id(), complex_cpe_obj.getVulnerable(), null);
                                        // Putting CPE node to CPE object into database
                                        session.save(node_to_cpe);
                                    }
                                }
                                // Following is the basic CPE case
                                else {
                                    // If the basic CPE object does exist, just the connection will be made
                                    cpe_db = (extended_mitre.cpe.CPEobject) session.get(extended_mitre.cpe.CPEobject.class, basic_cpe_id);
                                    if (cpe_db != null) {
                                        if (session.get(extended_mitre.cpe.CPEnodeToCPE.class, (obj.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId())) == null) {
                                            // Creating connection between basic CPE object and CVE
                                            extended_mitre.cpe.CPEnodeToCPE node_to_cpe = new extended_mitre.cpe.CPEnodeToCPE((obj.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId()), null, node_obj, obj.getMeta_data_id(), complex_cpe_obj.getVulnerable(), cpe_db);
                                            // Putting CPE node to CPE object into database
                                            session.save(node_to_cpe);
                                        }
                                    }
                                    // If the basic CPE object doesn't exist, it will be created and put into database
                                    else {
                                        cpe_db = extended_mitre.cpe.CPEobject.cpeUriToObject(basic_cpe_id);
                                        session.save(cpe_db);
                                        // Creating connection between basic CPE object and CVE
                                        extended_mitre.cpe.CPEnodeToCPE node_to_cpe = new extended_mitre.cpe.CPEnodeToCPE((obj.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId()), null, node_obj, obj.getMeta_data_id(), complex_cpe_obj.getVulnerable(), cpe_db);
                                        // Putting CPE node to CPE object into database
                                        session.save(node_to_cpe);
                                    }
                                }
                            }
                        }
                    } else if (node_obj != null) {
                        // Putting CPE node object into database
                        node_obj.setCve_obj(obj);
                        session.save(node_obj);
                    }
                }
                for (extended_mitre.cve.ReferenceObject ref_obj : obj.getReferences()) {
                    // Putting CVE reference object into database
                    ref_obj.setCve_obj(obj);
                    session.save(ref_obj);
                }
                // Ensuring optimalization
                if (refresh % 250 == 0) {
                    txv.commit();
                    session.close();
                    session = sf.openSession();
                    txv = session.beginTransaction();
                }
            }
            // Committing transaction, closing session and session factory
            if (txv.isActive()) txv.commit();
            if (session.isOpen()) session.close();
            sf.close();
            System.out.println("Actualization of CVE and CPE data done");
        }
        // If the database structure is basic, following code will be executed
        else if (db_exists) {
            // Creating configuration, session factory, session and transaction
            Configuration con = new Configuration().configure().addAnnotatedClass(basic_mitre.cve.CVEobject.class).addAnnotatedClass(basic_mitre.cpe.CPEobject.class)
                    .addAnnotatedClass(basic_mitre.cvss.CVSS2object.class).addAnnotatedClass(basic_mitre.cvss.CVSS3object.class).addAnnotatedClass(basic_mitre.cpe.CPEnodeObject.class)
                    .addAnnotatedClass(basic_mitre.cve.ReferenceObject.class).addAnnotatedClass(basic_mitre.cpe.CPEcomplexObj.class).addAnnotatedClass(basic_mitre.cpe.CPEnodeToCPE.class);
            ServiceRegistry reg = new StandardServiceRegistryBuilder().applySettings(con.getProperties()).build(); // basic structure of the database
            SessionFactory sf = con.buildSessionFactory(reg);
            Session session = sf.openSession();
            Transaction txv = session.beginTransaction();
            // Ensuring optimalization
            int refresh = 0;
            System.out.println("Basic structure of the database detected, actualization of CVE and CPE data started");
            // Parsing CVE and CPE data from input file
            List<basic_mitre.cve.CVEobject> cve_objs = basic_mitre.cve.CVEobject.CVEjsonToObjects(update_file);
            // List for removing objects that will be updated now later on
            List<basic_mitre.cve.CVEobject> cves_to_remove = new ArrayList<>();
            for (basic_mitre.cve.CVEobject cve_obj : cve_objs) {
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

                    // ---

                    // Removing object that was updated now
                    cves_to_remove.add(cve_obj);
                }
            }
            // Removing all objects, that has been updated until now
            cve_objs.removeAll(cves_to_remove);
            // If the CVE object is new, it is put into the database
            for (basic_mitre.cve.CVEobject obj : cve_objs) {
                refresh++;
                // Putting CVSS v2 object into database
                if (obj.getCvss_v2() != null) session.save(obj.getCvss_v2());
                // Putting CVSS v3 object into database
                if (obj.getCvss_v3() != null) session.save(obj.getCvss_v3());
                // Putting CVE object into database
                session.save(obj);
                // Putting CPE node objects into database
                for (basic_mitre.cpe.CPEnodeObject node_obj : obj.getCpe_nodes()) {
                    if (node_obj != null && node_obj.getComplex_cpe_objs() != null) {
                        // Putting CPE node object into database
                        node_obj.setCve_obj(obj);
                        session.save(node_obj);
                        for (basic_mitre.cpe.CPEcomplexObj complex_cpe_obj : node_obj.getComplex_cpe_objs()) {
                            if (complex_cpe_obj != null) {
                                // Making basic CPE id for creating or getting CPE object later on
                                String basic_cpe_id = complex_cpe_obj.getCpe_id();
                                // ensuring unique ID of complex CPE object
                                if (complex_cpe_obj.getVersion_start_including() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#star_in_" + complex_cpe_obj.getVersion_start_including());
                                }
                                if (complex_cpe_obj.getVersion_start_excluding() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#star_ex_" + complex_cpe_obj.getVersion_start_excluding());
                                }
                                if (complex_cpe_obj.getVersion_end_including() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#end_in_" + complex_cpe_obj.getVersion_end_including());
                                }
                                if (complex_cpe_obj.getVersion_end_excluding() != null) {
                                    complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id() + "#end_ex_" + complex_cpe_obj.getVersion_end_excluding());
                                }

                                basic_mitre.cpe.CPEcomplexObj compl_cpe_db = null;
                                basic_mitre.cpe.CPEobject cpe_db = null;
                                // Figuring out if it will be complex or basic CPE object - following is the complex CPE case
                                if (complex_cpe_obj.getVersion_end_excluding() != null || complex_cpe_obj.getVersion_start_excluding() != null ||
                                        complex_cpe_obj.getVersion_end_including() != null || complex_cpe_obj.getVersion_start_including() != null) {
                                    compl_cpe_db = (basic_mitre.cpe.CPEcomplexObj) session.get(basic_mitre.cpe.CPEcomplexObj.class, complex_cpe_obj.getCpe_id());
                                    // Making connection if the complex CPE object already exists
                                    if (compl_cpe_db != null) {
                                        if (session.get(basic_mitre.cpe.CPEnodeToCPE.class, (obj.getMeta_data_id() + "#" + compl_cpe_db.getCpe_id() + "#" + node_obj.getId())) == null) {
                                            // Creating connection between CPE and CVE
                                            basic_mitre.cpe.CPEnodeToCPE node_to_cpe = new basic_mitre.cpe.CPEnodeToCPE((obj.getMeta_data_id() + "#" + compl_cpe_db.getCpe_id() + "#" + node_obj.getId()), compl_cpe_db, node_obj, obj.getMeta_data_id(), complex_cpe_obj.getVulnerable(), null);
                                            // Putting CPE node to CPE object into database
                                            session.save(node_to_cpe);
                                        }
                                    }
                                    // Creating new complex CPE object if it doesn't exist
                                    else {
                                        // Creating basic CPE object to connect with if it doesn't exist
                                        cpe_db = (basic_mitre.cpe.CPEobject) session.get(basic_mitre.cpe.CPEobject.class, basic_cpe_id);
                                        if (cpe_db == null) {
                                            cpe_db = basic_mitre.cpe.CPEobject.cpeUriToObject(basic_cpe_id);
                                            session.save(cpe_db);
                                        }
                                        complex_cpe_obj.setCpe_objs(new ArrayList<>());
                                        // Making connection between complex CPE object and basic CPE object
                                        complex_cpe_obj.getCpe_objs().add(cpe_db);
                                        // Ensuring unique ID and putting complex CPE object into database
                                        complex_cpe_obj.setCpe_id(complex_cpe_obj.getCpe_id()+"#"+obj.getMeta_data_id());
                                        session.save(complex_cpe_obj);
                                        // Making connection between complex CPE object and CVE object
                                        basic_mitre.cpe.CPEnodeToCPE node_to_cpe = new basic_mitre.cpe.CPEnodeToCPE((obj.getMeta_data_id()+"#"+complex_cpe_obj.getCpe_id()+"#"+node_obj.getId()), complex_cpe_obj, node_obj, obj.getMeta_data_id(), complex_cpe_obj.getVulnerable(), null);
                                        // Putting CPE node to CPE object into database
                                        session.save(node_to_cpe);
                                    }
                                }
                                // Following is the basic CPE case
                                else {
                                    // If the basic CPE object does exist, just the connection will be made
                                    cpe_db = (basic_mitre.cpe.CPEobject) session.get(basic_mitre.cpe.CPEobject.class, basic_cpe_id);
                                    if (cpe_db != null) {
                                        if (session.get(basic_mitre.cpe.CPEnodeToCPE.class, (obj.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId())) == null) {
                                            // Creating connection between basic CPE object and CVE
                                            basic_mitre.cpe.CPEnodeToCPE node_to_cpe = new basic_mitre.cpe.CPEnodeToCPE((obj.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId()), null, node_obj, obj.getMeta_data_id(), complex_cpe_obj.getVulnerable(), cpe_db);
                                            // Putting CPE node to CPE object into database
                                            session.save(node_to_cpe);
                                        }
                                    }
                                    // If the basic CPE object doesn't exist, it will be created and put into database
                                    else {
                                        cpe_db = basic_mitre.cpe.CPEobject.cpeUriToObject(basic_cpe_id);
                                        session.save(cpe_db);
                                        // Creating connection between basic CPE object and CVE
                                        basic_mitre.cpe.CPEnodeToCPE node_to_cpe = new basic_mitre.cpe.CPEnodeToCPE((obj.getMeta_data_id()+"#"+cpe_db.getCpe_id()+"#"+node_obj.getId()), null, node_obj, obj.getMeta_data_id(), complex_cpe_obj.getVulnerable(), cpe_db);
                                        // Putting CPE node to CPE object into database
                                        session.save(node_to_cpe);
                                    }
                                }
                            }
                        }
                    } else if (node_obj != null) {
                        // Putting CPE node object into database
                        node_obj.setCve_obj(obj);
                        session.save(node_obj);
                    }
                }
                for (basic_mitre.cve.ReferenceObject ref_obj : obj.getReferences()) {
                    // Putting CVE reference object into database
                    ref_obj.setCve_obj(obj);
                    session.save(ref_obj);
                }
                // Ensuring optimalization
                if (refresh % 250 == 0) {
                    txv.commit();
                    session.close();
                    session = sf.openSession();
                    txv = session.beginTransaction();
                }
            }
            // Committing transaction, closing session and session factory
            if (txv.isActive()) txv.commit();
            if (session.isOpen()) session.close();
            sf.close();
            System.out.println("Actualization of CVE and CPE data done");
        }
        // If the database doesn't contain any table, nothing will happen
        else System.out.println("Database structure doesn't exist, it needs to be filled first, nothing will happen now");
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
