import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashingExample {

    public static void main(String[] args) {
        String data = "Detta är ett test för hashing i Java";
        try {
            // Skapa en SHA-256 hash av strängen "data"
            String hashValue = generateHash(data, "SHA-256");
            System.out.println("SHA-256 hash: " + hashValue);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Fel: Algoritmen finns inte.");
        }
    }

    // Metod för att generera hash med en given algoritm (t.ex. SHA-256)
    public static String generateHash(String data, String algorithm) throws NoSuchAlgorithmException {
        // Skapa en instans av MessageDigest för den givna algoritmen
        MessageDigest digest = MessageDigest.getInstance(algorithm);

        // Mata in datan till hash-funktionen
        byte[] hashBytes = digest.digest(data.getBytes());

        // Konvertera bytes till en läsbar form (Base64 eller hexadecimal)
        return bytesToHex(hashBytes); // Alternativt: Base64.getEncoder().encodeToString(hashBytes);
    }

    // Metod för att konvertera bytes till en hex-sträng
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
