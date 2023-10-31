import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.io.File;
import java.io.FileInputStream;

public class AESRC4 {

    private final int DATA_LENGTH = 128;
    private Cipher encryptionAESCipher;


    public static void main(String[] args) {
        try {
            //File path
            String filepath = "/Users/cabral/Desktop/Homework 4/Tests/File1.txt";
            File file = new File(filepath);
            //Read the content inside the file
            BufferedReader br = new BufferedReader(new FileReader(file));
            String line;
            StringBuilder fullContent = new StringBuilder();
            while ((line = br.readLine()) != null) {
                fullContent.append(line).append(System.lineSeparator());
            }
            String content = fullContent.toString(); //Save the content to a variable
            System.out.println("\nOriginal Plaintext:" + content);
            //Set the initial key for the AES
            AESRC4 aes_encryption = new AESRC4();
            String key1 = "LoveisallyouneedLoveisallyouneeT";
            SecretKey keyAES = aes_encryption.keyGenerationAES(key1);
            System.out.println(key1.getBytes().length * 8+"-bit AES Original Key: " + key1);
            //Encrypt the file using AES and key 1
            String ciphertext1 = aes_encryption.encryptAES(content, keyAES);
            System.out.println("\n1) AES Ciphertext: " + ciphertext1);
            //Set initial key for the RC4
            String key2 = "CometogheterrightnowoveV"; //24 chars
            byte[] secKey = Base64.getDecoder().decode(key2);
            SecretKey finalRC4key = new SecretKeySpec(secKey, 0, secKey.length, "RC4");
            System.out.println("\n" + key2.getBytes().length * 8+"-bit RC4 Original Key: " + key2);

            //Encrypt the ciphertext using RC4
            String ciphertext2 = encryptRC4(ciphertext1, finalRC4key);
            System.out.println("\n2) RC4 Ciphertext: " + ciphertext2);

            //Decrypt data uisng RC4
            String ciphertex2 = decryptRC4(finalRC4key, ciphertext2);
            System.out.println("\n3) RC4 Decryption: " + ciphertex2);

            //Decrypt data uisng AES
            String decryptedData = aes_encryption.decryptAES(ciphertext1, keyAES);
            System.out.println("\n4) AES Decryption: " + decryptedData);

            //Save text to new file
            String newFile = "/Users/cabral/Desktop/Homework 4/Tests/File1.2.txt"; // Replace with the desired file name
            File newFileF = new File(newFile);
            BufferedWriter writer = new BufferedWriter(new FileWriter(newFileF));
            writer.write(ciphertex2);
            writer.close();

            System.out.println("Ciphertex 1 bits: " + ciphertext1.length() * 8);
            System.out.println("Ciphertex 2 bits: " + ciphertext2.length() * 8);
            System.out.println("\nOriginal File Size: " + file.length() * 8);
            System.out.println("File Size After AES: " + newFileF.length() * 8);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //-----------------------------AES---------------------------------------------
    public SecretKey keyGenerationAES(String originalKey) throws Exception {
        byte[] secretKey = Base64.getDecoder().decode(originalKey);
        SecretKey finalKeyAES = new SecretKeySpec(secretKey, 0, secretKey.length, "AES");
        return finalKeyAES;
    }
    public String encryptAES(String plaintext, SecretKey key) throws Exception {
        byte[] plaintextBytes = plaintext.getBytes();
        encryptionAESCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionAESCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionAESCipher.doFinal(plaintextBytes);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    public String decryptAES(String encryptedData, SecretKey key) throws Exception {
        byte[] dataInBytes = Base64.getDecoder().decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, encryptionAESCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }
    //-----------------------------RC4---------------------------------------------
    private static String encryptRC4(String plaintext, SecretKey secretKey) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher rc4 = Cipher.getInstance("ARCFOUR");
        rc4.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] ciphertextBytes = rc4.doFinal(plaintextBytes);
        String ciphertext = Base64.getEncoder().encodeToString(ciphertextBytes);
        return ciphertext;
    }

    public static String decryptRC4(SecretKey secretKey, String ciphertext) throws InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            NoSuchAlgorithmException{
        Cipher rc4 = Cipher.getInstance("ARCFOUR");
        byte[] newCiphertext = Base64.getDecoder().decode(ciphertext);
        rc4.init(Cipher.DECRYPT_MODE, secretKey, rc4.getParameters());
        byte[] byteDecryptedText = rc4.doFinal(newCiphertext);
        String plaintextBack = new String(byteDecryptedText);
        return plaintextBack;
    }
}


