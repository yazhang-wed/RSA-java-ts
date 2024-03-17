import javax.crypto.Cipher;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author: LBK
 * @date: 2024/3/14 17:29
 */
public class RSAKeyPairGenerator {

    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        String publicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        String privateKey = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        try {
            saveKeyToFile("src/main/resources/keypair/publicKey.pem", publicKey, true);
            saveKeyToFile("src/main/resources/keypair/privateKey.pem", privateKey, false);
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Public Key: " + publicKey);
        System.out.println("Private Key: " + privateKey);

        String encrypt = encrypt("Hello, world!", "src/main/resources/keypair/publicKey.pem");
        System.out.println("encrypt：" + encrypt);

        String decrypt = decrypt(encrypt, "src/main/resources/keypair/privateKey.pem");
        System.out.println("decrypt：" + decrypt);
    }

    public static void saveKeyToFile(String fileName, String key, boolean isPublic) throws IOException {
        try (FileWriter writer = new FileWriter(fileName)) {
            String header = isPublic ? "-----BEGIN PUBLIC KEY-----\n" : "-----BEGIN PRIVATE KEY-----\n";
            String footer = isPublic ? "\n-----END PUBLIC KEY-----\n" : "\n-----END PRIVATE KEY-----\n";

            writer.write(header);
            writer.write(key);
            writer.write(footer);
        }
    }

    private static String getKeyFromFile(String filePath) throws IOException {
        return new String(Files.readAllBytes(Paths.get(filePath))).replaceAll("-----BEGIN (.*?)-----", "")
                .replaceAll("-----END (.*?)-----", "")
                .replaceAll("\\s", "");
    }

    public static String decrypt(String data, String privateKeyPath) throws Exception {
        byte[] dataBytes = Base64.getDecoder().decode(data);
        String base64PrivateKey = getKeyFromFile(privateKeyPath);
        byte[] keyBytes = Base64.getDecoder().decode(base64PrivateKey);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);

        //  OAEP 填充方式；缺点：相对安全一些；优点：兼容性不太好；
        //  Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        // PKCS#1 v1.5 填充方式；缺点：相对来说没有 OAEP 安全；优点：兼容性好；
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(dataBytes));
    }

    public static String encrypt(String data, String publicKeyPath) throws Exception {
        byte[] dataBytes = data.getBytes();
        String base64PublicKey = getKeyFromFile(publicKeyPath);
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(spec);

        //  OAEP 填充方式；缺点：相对安全一些；优点：兼容性不太好；
        //  Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        // PKCS#1 v1.5 填充方式；缺点：相对来说没有 OAEP 安全；优点：兼容性好；
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(dataBytes));
    }

}
