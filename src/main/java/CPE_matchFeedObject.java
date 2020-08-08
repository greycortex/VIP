import com.google.gson.Gson;
import java.io.*;
import java.sql.*;
import java.util.ArrayList;


public class CPE_matchFeedObject {

    private static Connection db;
    private final Long id;
    private final String vendor;
    private final String product;
    private final String version;
    private final String update;
    private final String edition;
    private final String language;
    private final String swEdition;
    private final String targetSw;
    private final String targetHw;
    private final String other;

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

    public static ArrayList<String> parserToLineArrayList() {
        ArrayList<String> cpe23urilines = new ArrayList<>();
        ArrayList<CPE_matchFeedObject> obj_list = new ArrayList<CPE_matchFeedObject>();

        try(BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\Xarf\\Desktop\\VIP\\exclude\\nvdcpematch-1.0.json"))) {
            for(String line; (line = br.readLine()) != null; ) {
                if(line.contains("cpe23Uri")){
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

        for (String line : cpe23urilines){

            String[] splitstr = line.split(":");

            for (int i = 0; i<splitstr.length; i++){
                if (splitstr[i].equals("*") || splitstr[i].equals("*\",") || splitstr[i].equals("*\"")){
                    splitstr[i] = null;
                }
                if (splitstr[i] != null){
                    splitstr[i] = splitstr[i].replace("'","''");
                    splitstr[i] = splitstr[i].replace("\\\\","");
                    splitstr[i] = splitstr[i].replace("!",""); /*Je obtizne najit specialni znaky, ktere by se daly nahradit, radeji to necham takto, aby
                                                                                   se pak nic neznicilo a mohlo se co nejlepe vyhledavat*/
                }
            }
            if (splitstr[13] != null){
                splitstr[13] = splitstr[13].replace("\",","");
                splitstr[13] = splitstr[13].replace("\"","");
            }

            CPE_matchFeedObject obj = new CPE_matchFeedObject(splitstr[4],splitstr[5],splitstr[6],splitstr[7],splitstr[8],splitstr[9],splitstr[10],splitstr[11],splitstr[12],splitstr[13]);
            obj_list.add(obj);
        }
        return obj_list;
    }

    public static void obj_listToDatabase() throws ClassNotFoundException, SQLException, FileNotFoundException {
        ArrayList<CPE_matchFeedObject> obj_list = stringArrayListToObjectArraylist();
        ArrayList<String> url_conn = new ArrayList<>();

        try(BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\Xarf\\Desktop\\VIP\\exclude\\dbconnection.txt"))) { // "exclude\dbconnection.txt" -> umisteni souboru s connection url
            for(String line; (line = br.readLine()) != null; ) {
                url_conn.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        Class.forName("org.postgresql.Driver");

        db = DriverManager.getConnection(url_conn.get(0));

        for (CPE_matchFeedObject object : obj_list){
            Statement stat = db.createStatement();
            stat.execute("INSERT INTO cpe_match_feed_objects (vendor, product, version, update, edition, language, swedition, targetsw, targethw, other) " +
                    "VALUES ('"+object.vendor+"', '"+object.product+"', '"+object.version+"', '"+object.update+"', '"+object.edition+"', '"+object.language+"', '"+object.swEdition+"', " +
                    "'"+object.targetSw+"', '"+object.targetHw+"', '"+object.other+"')");
        }
        db.close();
    }

    public static void comparingForUpdate() throws ClassNotFoundException, SQLException, NullPointerException, FileNotFoundException {
        ArrayList<CPE_matchFeedObject> compared_objects = stringArrayListToObjectArraylist();
        ArrayList<String> url_conn = new ArrayList<>();
        int duplicity;

        try(BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\Xarf\\Desktop\\VIP\\exclude\\dbconnection.txt"))) {
            for(String line; (line = br.readLine()) != null; ) {
                url_conn.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        for (CPE_matchFeedObject obj : compared_objects){
            ArrayList<CPE_matchFeedObject> objects_to_compare = new ArrayList<>();

            Class.forName("org.postgresql.Driver");
            db = DriverManager.getConnection(url_conn.get(0));
            Statement stat = db.createStatement();
            ResultSet result = stat.executeQuery("SELECT * FROM cpe_match_feed_objects WHERE vendor = '"+obj.vendor+"'");
            while(result.next()) {
                CPE_matchFeedObject obj_to_compare = new CPE_matchFeedObject(result.getString(2),result.getString(3),result.getString(4),result.getString(5),result.getString(6)
                        ,result.getString(7),result.getString(8),result.getString(9),result.getString(10),result.getString(11));
                objects_to_compare.add(obj_to_compare);
            }
            db.close();

            duplicity = 0;
            for (CPE_matchFeedObject compared_obj : objects_to_compare){ // ???
                if(duplicity==0){
                    System.out.println("Jop");
                }
            }
            if(duplicity != 0){
                Class.forName("org.postgresql.Driver");
                db = DriverManager.getConnection(url_conn.get(0));

                Statement addstat = db.createStatement();
                addstat.execute("INSERT INTO cpe_match_feed_objects (vendor, product, version, update, edition, language, swedition, targetsw, targethw, other) " +
                        "VALUES ('"+obj.vendor+"', '"+obj.product+"', '"+obj.version+"', '"+obj.update+"', '"+obj.edition+"', '"+obj.language+"', '"+obj.swEdition+"', " +
                        "'"+obj.targetSw+"', '"+obj.targetHw+"', '"+obj.other+"')");
                db.close();
            }
        }
    }

    @Override
    public String toString() {
        return "CPE_matchFeedObject{" +
                "vendor='" + vendor + '\'' +
                ", product='" + product + '\'' +
                ", version='" + version + '\'' +
                ", update='" + update + '\'' +
                ", edition='" + edition + '\'' +
                ", language='" + language + '\'' +
                ", swEdition='" + swEdition + '\'' +
                ", targetSw='" + targetSw + '\'' +
                ", targetHw='" + targetHw + '\'' +
                ", other='" + other + '\'' +
                '}';
    }
}