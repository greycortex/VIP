public class Main {

    public static void main(String[] args) {
        System.out.println("Welcome to the VIP application");
        System.out.println(CVEobject.CVEjsonToObjects("exclude/nvdcve-1.1-2002.json"));
        //System.out.println(CVEobject.CVEjsonToObjects("exclude/nvdcve-1.1-2009.json").size());
    }
}
