package CryptoClasses;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;

/**
 * Class that handles the decryption of SealedObjects by using a private key and RSA Cipher.
 * Based on PKI infrastructure - private key used for decryption, public key used for encryption.
 *
 * @author Arvin Moshfegh
 * @version 3.0
 */
public class DecryptionHandler {
    private PrivateKey privateKey;
    private Cipher rsaCipher;

    /**
     * Constructor for DecryptionHandler. Sets the private key being used and generates a new RSA cipher with the key.
     *
     * @param privateKey RSA Private key used for decryption.
     * @throws InvalidKeyException if the key cannot be used to create RSA cipher.
     */
    public DecryptionHandler(PrivateKey privateKey) throws InvalidKeyException {
        this.privateKey = privateKey;
        this.rsaCipher = createRSACipher();
    }

    /**
     * Decrypts a SealedObject and extracts the SignedObject inside of it.
     *
     * @param encryptedSecretKey Symmetric secret key used to seal the SealedObject
     * @param sealedObject       SealedObject containing the SignedObject
     * @return Returns the SignedObject extracted from SealedObject.
     */
    public SignedObject decryptSignedObject(byte[] encryptedSecretKey, SealedObject sealedObject) {
        return (SignedObject) decryptData(encryptedSecretKey, sealedObject);
    }


    /**
     * Creates an RSA cipher with the private RSA key and sets it into DECRYPT_MODE.
     *
     * @return Returns the generated RSA Cipher to be used for decryption.
     * @throws InvalidKeyException If the wrong key has been used or the key uses a different algorithm.
     */
    private Cipher createRSACipher() throws InvalidKeyException {
        Cipher rsaCipher = null;
        try {
            rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException err) {
            System.err.println("Could not get instance of cipher");
            err.printStackTrace();
        }
        return rsaCipher;
    }

    /**
     * Decrypts the data inside the SealedObject. The project started off with only encryption/decryption, so this method
     * returns an Object that can be casted later. Due to signatures being involved now it is casted in the public method
     * to a SignedObject, but this method could be used if the SealedObject contains any other serializable objects.
     *
     * @param encryptedSecretKeyByte Symmetric encryption key used to seal the SealedObject.
     * @param sealedObject           SealedObject containing the Object.
     * @return Returns an Object. Should be casted for any object that is expected.
     */
    private Object decryptData(byte[] encryptedSecretKeyByte, SealedObject sealedObject) {
        Object object = null;
        byte[] decryptedSecretKeyByte;
        try {
            decryptedSecretKeyByte = rsaCipher.doFinal(encryptedSecretKeyByte);
            SecretKey secretKey = new SecretKeySpec(decryptedSecretKeyByte, "AES");
            object = sealedObject.getObject(secretKey);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            System.err.println("Could not decrypt secret key. Check that you are using the correct" +
                    "private key to decrypt it");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException | ClassNotFoundException err) {
            System.err.println("Algorithm or class not found");
            err.printStackTrace();
        } catch (InvalidKeyException err) {
            System.err.println("Invalid key to decrypt");
            err.printStackTrace();
        } catch (IOException err) {
            System.err.println("Could not get object");
            err.printStackTrace();
        }
        return object;
    }
}