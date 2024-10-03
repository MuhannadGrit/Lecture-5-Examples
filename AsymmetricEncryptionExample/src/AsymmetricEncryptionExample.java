import java.security.*;
import javax.crypto.Cipher;
import java.util.Base64;

public class AsymmetricEncryptionExample {

    public static void main(String[] args) throws Exception {
        // Generera ett RSA-nyckelpar
        KeyPair keyPair = generateRSAKeyPair();

        // Klartext att kryptera
        String plainText = "Detta är ett test för asymmetrisk kryptering";

        // Kryptera med offentlig nyckel
        String encryptedText = encryptWithPublicKey(plainText, keyPair.getPublic());
        System.out.println("Krypterad text med offentlig nyckel: " + encryptedText);

        // Dekryptera med privat nyckel
        String decryptedText = decryptWithPrivateKey(encryptedText, keyPair.getPrivate());
        System.out.println("Dekrypterad text med privat nyckel: " + decryptedText);

        // Skapa och verifiera en digital signatur
        String signature = generateDigitalSignature(plainText, keyPair.getPrivate());
        System.out.println("Digital signatur: " + signature);

        boolean isVerified = verifyDigitalSignature(plainText, signature, keyPair.getPublic());
        System.out.println("Signatur verifierad: " + isVerified);
    }

    // 1. Generera ett RSA-nyckelpar
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Nyckelstorlek på 2048 bitar (säker standard)
        return keyGen.generateKeyPair();
    }

    // 2. Kryptera med offentlig nyckel
    public static String encryptWithPublicKey(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 3. Dekryptera med privat nyckel
    public static String decryptWithPrivateKey(String encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }

    // 4. Skapa en digital signatur med privat nyckel
    public static String generateDigitalSignature(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] digitalSignature = signature.sign();
        return Base64.getEncoder().encodeToString(digitalSignature);
    }

    // 5. Verifiera den digitala signaturen med offentlig nyckel
    public static boolean verifyDigitalSignature(String data, String signatureStr, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data.getBytes());
        byte[] digitalSignature = Base64.getDecoder().decode(signatureStr);
        return signature.verify(digitalSignature);
    }
}
