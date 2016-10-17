import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import javax.crypto.Cipher;


public class RSALibrary {

    // String to hold name of the encryption algorithm.
    public final String ALGORITHM = "RSA";

    //String to hold the name of the private key file.
    public static final String PRIVATE_KEY_FILE = "./private.key";

    // String to hold name of the public key file.
    public static final String PUBLIC_KEY_FILE = "./public.key";


  /* Generates an RSA key pair (a public and a private key) of 1024 bits length */
  /* Stores the keys in the files defined by PUBLIC_KEY_FILE and PRIVATE_KEY_FILE */
  /* Throws IOException */

    public void generateKeys() throws IOException {

        try {

            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic(); 

              FileOutputStream privateFileOutputStream = new FileOutputStream(PRIVATE_KEY_FILE);
              ObjectOutputStream privateOutputStream = new ObjectOutputStream(privateFileOutputStream);
              privateOutputStream.writeObject(privateKey);
              privateOutputStream.close();
                
              FileOutputStream publicFileOutputStream = new FileOutputStream(PUBLIC_KEY_FILE);
              ObjectOutputStream publicOutputStream = new ObjectOutputStream(publicFileOutputStream);
              publicOutputStream.writeObject(publicKey);
              publicOutputStream.close();

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Exception: " + e.getMessage());
            e.printStackTrace();
            System.exit(-1);
        }
    }


  /* Encrypts a plaintext using an RSA public key. */
  /* Arguments: the plaintext and the RSA public key */
  /* Returns a byte array with the ciphertext */

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
        return ciphertext;
    }

    /* Decrypts a ciphertext using an RSA private key. */
    /* Arguments: the ciphertext and the RSA private key */
    /* Returns a byte array with the plaintext */

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

    /* Signs a plaintext using an RSA private key. */
    /* Arguments: the plaintext and the RSA private key */
    /* Returns a byte array with the signature */

    public byte[] sign(byte[] plaintext, PrivateKey key) {

        byte[] signedInfo = null;

        try {
            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");

            signature.initSign(key);
            signature.update(plaintext);
            signedInfo = signature.sign();

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return signedInfo;
    }

  /* Verifies a signature over a plaintext */
  /* Arguments: the plaintext, the signature to be verified (signed) 
  /* and the RSA public key */
  /* Returns TRUE if the signature was verified, false if not */

    public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {

        boolean result = false;

        try {

            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");

            // initialize the signature object with the public key
            signature.initVerify(key);

            //set plaintext as the bytes to be verified
            signature.update(plaintext);

            // Verify the signature (signed). Store the outcome in the boolean result
            result = signature.verify(signed);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return result;
    }

}


