import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SaltedHashExample {

    public static void main(String[] args) throws Exception {
        String password = "mitt_säkra_lösenord";

        // Generera ett salt
        byte[] salt = generateSalt();

        // Generera en hash med saltet
        String saltedHash = generateSaltedHash(password, salt, "SHA-256");

        System.out.println("Saltad hash (SHA-256): " + saltedHash);
    }

    // Generera ett slumpmässigt salt
    public static byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; // Saltet är 16 bytes
        random.nextBytes(salt);
        return salt;
    }

    // Generera en saltad hash
    public static String generateSaltedHash(String data, byte[] salt, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);

        // Lägg till saltet till datan
        digest.update(salt);

        // Hasha lösenordet med saltet
        byte[] hashBytes = digest.digest(data.getBytes());

        // Konvertera hash till en sträng (t.ex. Base64)
        return Base64.getEncoder().encodeToString(hashBytes);
    }
}
