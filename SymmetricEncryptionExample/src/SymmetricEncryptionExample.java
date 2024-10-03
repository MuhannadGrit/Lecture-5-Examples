import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionExample {

    public static void main(String[] args) throws Exception {
        // Klartext att kryptera
        String plainText = "Detta är ett test för symmetrisk kryptering";

        // Generera en AES nyckel en gång
        SecretKey aesKey = generateAESKey();

        // AES-kryptering och dekryptering
        String aesEncrypted = AESKryptering(plainText, aesKey);
        String aesDecrypted = AESDekryptering(aesEncrypted, aesKey);
        System.out.println("AES Krypterad text: " + aesEncrypted);
        System.out.println("AES Dekrypterad text: " + aesDecrypted);

        // DES-kryptering och dekryptering
        SecretKey desKey = generateDESKey();
        String desEncrypted = DESKryptering(plainText, desKey);
        String desDecrypted = DESDekryptering(desEncrypted, desKey);
        System.out.println("DES Krypterad text: " + desEncrypted);
        System.out.println("DES Dekrypterad text: " + desDecrypted);

        // 3DES-kryptering och dekryptering
        SecretKey tripleDesKey = generateTripleDESKey();
        String tripleDesEncrypted = TripleDESKryptering(plainText, tripleDesKey);
        String tripleDesDecrypted = TripleDESDekryptering(tripleDesEncrypted, tripleDesKey);
        System.out.println("3DES Krypterad text: " + tripleDesEncrypted);
        System.out.println("3DES Dekrypterad text: " + tripleDesDecrypted);

        // Blowfish-kryptering och dekryptering
        SecretKey BlowfishKey = generateBlowfishKey();
        String BlowfishEncrypted = BlowfishKryptering(plainText, BlowfishKey);
        String BlowfishDecrypted = BlowfishDekryptering(BlowfishEncrypted, BlowfishKey);
        System.out.println("Blow Fish Krypterad text: " + BlowfishEncrypted);
        System.out.println("Blow Fish Dekrypterad text: " + BlowfishDecrypted);
    }

    // AES nyckelgenerering
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    // AES krypteringsmetod
    public static String AESKryptering(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // AES dekrypteringsmetod
    public static String AESDekryptering(String encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }

    // DES nyckelgenerering
    public static SecretKey generateDESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        return keyGen.generateKey();
    }

    // DES krypteringsmetod
    public static String DESKryptering(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // DES dekrypteringsmetod
    public static String DESDekryptering(String encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }

    // 3DES nyckelgenerering
    public static SecretKey generateTripleDESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DESede"); // DESede för 3DES
        return keyGen.generateKey();
    }

    // Generera Blowfish-nyckel
    public static SecretKey generateBlowfishKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
        keyGen.init(128); // Nyckellängd kan variera, t.ex. 128, 192 eller 256 bitar
        return keyGen.generateKey();
    }

    // 3DES krypteringsmetod
    public static String TripleDESKryptering(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 3DES dekrypteringsmetod
    public static String TripleDESDekryptering(String encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }

    // Blowfish krypteringsmetod
    public static String BlowfishKryptering(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Blowfish dekrypteringsmetod
    public static String BlowfishDekryptering(String encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }
}
