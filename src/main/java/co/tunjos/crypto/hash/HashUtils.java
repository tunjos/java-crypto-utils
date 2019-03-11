package co.tunjos.crypto.hash;

public class HashUtils {
    private static HashUtils ourInstance = new HashUtils();

    public static HashUtils getInstance() {
        return ourInstance;
    }

    private HashUtils() {
    }
}
