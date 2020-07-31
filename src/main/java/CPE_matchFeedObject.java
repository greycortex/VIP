import com.google.gson.Gson;
import java.io.FileReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;

public class CPE_matchFeedObject {

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
                               String swEdition, String targetSw, String targetHw, String other){
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

    public static ArrayList<CPE_matchFeedObject> cpeMatchFeedParser() throws FileNotFoundException {
        Gson gson = new Gson();
        ArrayList<CPE_matchFeedObject> obj_list = new ArrayList<CPE_matchFeedObject>();
        /*Reader reader = new FileReader("C:\\Users\\Xarf\\Desktop\\nvdcpematch-1.0.json");*/
        System.out.println(obj_list);
        return obj_list;
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