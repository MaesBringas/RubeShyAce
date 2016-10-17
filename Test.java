import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class Test {


    public static void main(String args[]) {

        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        byte[] plainText = null;
        byte[] cipherText = null;
        byte[] decryptedPlainText = null;
        boolean isVerified = false;

        RSALibrary rsa = new RSALibrary();

        try {
            String secretContent = new Scanner(new File("plaintext.txt")).useDelimiter("\\Z").next();
            System.out.println("Secret string >> " + secretContent);
            plainText = secretContent.getBytes();

            rsa.generateKeys();

            File filePublicKey = new File("./public.key");
            File filePrivateKey = new File("./private.key");

            if (filePublicKey.exists() && filePublicKey.isFile()) {
                System.out.println("INFO: Public key already created. The file will be overwritten");
                FileInputStream fileInput = new FileInputStream(filePublicKey);
                ObjectInputStream objectInputStream = new ObjectInputStream(fileInput);
                publicKey = (PublicKey) objectInputStream.readObject();
                objectInputStream.close();
                cipherText = rsa.encrypt(plainText, publicKey);
                BufferedWriter ciphered = new BufferedWriter(new FileWriter("cipher.txt"));
                ciphered.write(cipherText.toString());
                ciphered.close();
            }

            if (filePrivateKey.exists() && filePrivateKey.isFile()) {
                System.out.println("INFO: Private key already created. The file will be overwritten");
                FileInputStream fileInput = new FileInputStream(filePrivateKey);
                ObjectInputStream objectInputStream = new ObjectInputStream(fileInput);
                privateKey = (PrivateKey) objectInputStream.readObject();
                objectInputStream.close();

                decryptedPlainText = rsa.decrypt(cipherText, privateKey);
                File decryptedFile = new File("decrypted.txt");
                FileOutputStream fop = new FileOutputStream(decryptedFile);
                fop.write(decryptedPlainText);
                fop.flush();
                fop.close();
            }

            byte[] signatureToBeVerified = rsa.sign(plainText, privateKey);
            System.out.println("Signature > " + signatureToBeVerified.toString());
            isVerified = rsa.verify(plainText, signatureToBeVerified, publicKey);
            System.out.println("Signature verification >  " + isVerified);

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

    }

}
