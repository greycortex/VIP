import java.io.FileNotFoundException;
import java.sql.SQLException;

public class Main {

    public static void main(String[] args) throws FileNotFoundException, SQLException, ClassNotFoundException {
        System.out.println("Welcome to the VIP application");
        CPE_matchFeedObject.obj_listToDatabase();
    }
}
