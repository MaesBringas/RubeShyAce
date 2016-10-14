import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;


public class RSALibrary {

    // String to hold name of the encryption algorithm.
    public final String ALGORITHM = "RSA";

    //String to hold the name of the private key file.
    public static final String PRIVATE_KEY_FILE = "private.key";

    // String to hold name of the public key file.
    public static final String PUBLIC_KEY_FILE = "public.key";


    /***********************************************************************************/
  /* Generates an RSA key pair (a public and a private key) of 1024 bits length */
  /* Stores the keys in the files defined by PUBLIC_KEY_FILE and PRIVATE_KEY_FILE */
  /* Throws IOException */

    /***********************************************************************************/
    public void generateKeys() throws IOException {

        try {

            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();

            File privateKey = new File(PRIVATE_KEY_FILE);
            File publicKey = new File(PUBLIC_KEY_FILE);

            if (privateKey.getParentFile() != null) {
                privateKey.getParentFile().mkdirs();
            }
            privateKey.createNewFile();

            if (publicKey.getParentFile() != null) {
                publicKey.getParentFile().mkdirs();
            }
            publicKey.createNewFile();

            ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(privateKey));
            privateKeyOS.writeObject(keyPair.getPrivate().getEncoded());
            privateKeyOS.close();

            ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKey));
            publicKeyOS.writeObject(keyPair.getPublic().getEncoded());
            publicKeyOS.close();

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Exception: " + e.getMessage());
            e.printStackTrace();
            System.exit(-1);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSALibrary rsa = new RSALibrary();
        try {
            final String originalText = "Text to be encrypted ";
            rsa.generateKeys();
            PublicKey pub = rsa.readPublic(PUBLIC_KEY_FILE);
            PrivateKey priv = rsa.readPrivate(PRIVATE_KEY_FILE);
            rsa.encrypt(originalText.getBytes(), pub);
            rsa.decrypt(originalText.getBytes(), priv);

        } catch (InvalidKeySpecException e) {
            System.err.println("Key error, check Key pair generation and encoding");
        } catch (NoSuchAlgorithmException) {
            System.err.println("Algorithm error, check the implementation");
        }

    }

    public byte[] readFile(String file) throws IOException {
        Path path;
        try {
            path = Paths.get(file);
            return Files.readAllBytes(path);
        } catch (IOException) {
            System.err.println("I/O error with " + path);
        }

    }

    public PublicKey readPublic(String filePublic) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        X509EncodedKeySpec publicS;
        KeyFactory key;

        try {
            publicS = new X509EncodedKeySpec(readFile(PUBLIC_KEY_FILE));
            key = KeyFactory.getInstance(ALGORITHM);
            return key.generatePublic(publicS);
        } catch (NoSuchAlgorithmException) {
            System.err.println("Algorithm error, check the implementatio");
        } catch (IOException){
            System.err.println("I/O error with " + publicS);
        } catch (InvalidKeySpecException) {
            System.err.println("Invalid key " + key);
        }

    }

    public PrivateKey readPrivate(String filePriv) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        try {
            PKCS8EncodedKeySpec privateS = new PKCS8EncodedKeySpec(readFile(PRIVATE_KEY_FILE));
            KeyFactory key = KeyFactory.getInstance(ALGORITHM);
            return key.generatePrivate(privateS);



    } catch (NoSuchAlgorithmException) {
        System.err.println("Algorithm error, check the implementatio");
    } catch (IOException){
        System.err.println("I/O error with " + publicS);
    } catch (InvalidKeySpecException) {
        System.err.println("Invalid key " + key);
    }
    }


    /***********************************************************************************/
  /* Encrypts a plaintext using an RSA public key. */
  /* Arguments: the plaintext and the RSA public key */
  /* Returns a byte array with the ciphertext */

    /***********************************************************************************/
    public byte[] encrypt(byte[] plaintext, PublicKey key) {

        byte[] ciphertext = null;

        try {

            // Gets an RSA cipher object
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // initialize and encrypt
            cipher.init(Cipher.ENCRYPT_MODE, key);
            ciphertext = cipher.doFinal(plaintext);

        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(ciphertext);
        return ciphertext;
    }

    /***********************************************************************************/
    /* Decrypts a ciphertext using an RSA private key. */
    /* Arguments: the ciphertext and the RSA private key */
    /* Returns a byte array with the plaintext */

    /***********************************************************************************/
    public byte[] decrypt(byte[] ciphertext, PrivateKey key) {

        byte[] plaintext = null;

        try {
            // Gets an RSA cipher object
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            cipher.init(Cipher.DECRYPT_MODE, key);
            plaintext = cipher.doFinal(ciphertext);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        System.out.println(plaintext);

        return plaintext;
    }

    /***********************************************************************************/
    /* Signs a plaintext using an RSA private key. */
    /* Arguments: the plaintext and the RSA private key */
    /* Returns a byte array with the signature */

    /***********************************************************************************/
    public byte[] sign(byte[] plaintext, PrivateKey key) {

        byte[] signedInfo = null; // TODO

        try {
            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");

            signature.initSign(key);
            signature.update(plaintext);
            signature.sign();

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return signedInfo;
    }

    /***********************************************************************************/
  /* Verifies a signature over a plaintext */
  /* Arguments: the plaintext, the signature to be verified (signed) 
  /* and the RSA public key */
  /* Returns TRUE if the signature was verified, false if not */

    /***********************************************************************************/
    public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {

        boolean result = false;

        try {

            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");

            signature.initVerify(key);
            result = signature.verify(signed);
            System.out.println("Verified -> " + result);

            // TO-DO: initialize the signature object with the public key
            // ...

            // TO-DO: set plaintext as the bytes to be verified
            // ...

            // TO-DO: verify the signature (signed). Store the outcome in the boolean result
            // ...

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return result;
    }

}


