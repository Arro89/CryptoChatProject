package CryptoClasses;

import javax.crypto.*;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignedObject;

/**
 * Class that handles the encryption and creation of SealedObjects using the receivers public RSA key.
 * Based on PKI infrastructure - public key used for encryption, private key used for decryption.
 *
 * @author Arvin Moshfegh
 * @version 3.0
 */

public class EncryptionHandler {
    private PublicKey publicKey;
    private Cipher rsaCipher;
    private byte[] encryptedSecretKey;

    /**
     * @param publicKey Receivers public key used to encrypt messages with
     * @throws InvalidKeyException if the public key cannot be used to create RSA cipher.
     */
    public EncryptionHandler(PublicKey publicKey) throws InvalidKeyException {
        this.publicKey = publicKey;
        this.rsaCipher = createRSACipher();
    }

    /**
     * Gets a SealedObject containing a SignedObject (any information that is being transferred)
     *
     * @param signedObject SignedObject to be sealed.
     * @return returns SealedObject containing the signed data
     */
    public SealedObject getSealedObject(SignedObject signedObject) {
        return encryptData(signedObject);
    }

    /**
     * Used to get the secret key that was used to encrypt the message.
     *
     * @return Returns the encrypted secret key created when encrypting the message
     */
    public byte[] getEncryptedSecretKey() {
        return encryptedSecretKey;
    }

    /**
     * Encrypts data by using a symmetric key.
     * <p>
     * Creates a SealedObject that is encrypted with the symmetric key and encrypts the symmetric key
     * with the asymmetric key (public key of recipient). Can encrypt any serializable object.
     *
     * @param serializableObject A serializable object containing data to be sent
     * @return Returns SealedObject with encapsulated data
     */
    private SealedObject encryptData(Serializable serializableObject) {
        SealedObject sealedObject = null;
        try {
            SecretKey secretKey = createSecretKey();
            Cipher aesCipher = createAESCipher(secretKey);
            sealedObject = new SealedObject(serializableObject, aesCipher);
            byte[] secretKeyBytes = secretKey.getEncoded();
            System.out.println("secretKeyBytes" + secretKeyBytes.length);
            encryptedSecretKey = rsaCipher.doFinal(secretKeyBytes);
        } catch (InvalidKeyException err) {
            System.err.println("Wrong key for cipher");
            err.printStackTrace();
        } catch (IOException | IllegalBlockSizeException err) {
            System.err.println("Could not create sealed object");
            err.printStackTrace();
        } catch (BadPaddingException err) {
            System.err.println("Could not encrypt secret key");
            err.printStackTrace();
        } catch (NoSuchAlgorithmException err) {
            System.err.println("Algorithm not found for AES cipher");
            err.printStackTrace();
        } catch (NoSuchPaddingException err) {
            System.err.println("Error with padding for AES cipher");
            err.printStackTrace();
        }
        return sealedObject;
    }

    /**
     * Creates an RSA Cipher for asymmetric encryption with the public key of the receiver of the sealed object.
     * Used to encrypt the symmetric key so only the receiver can decrypt the symmetric.
     *
     * @return RSA cipher generated with the public key, in encrypt mode.
     * @throws InvalidKeyException if the key is invalid
     */
    private Cipher createRSACipher() throws InvalidKeyException {
        Cipher rsaCipher = null;
        try {
            rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        } catch (NoSuchPaddingException err) {
            System.err.println("Wrong padding");
            err.printStackTrace();
        } catch (NoSuchAlgorithmException err) {
            System.err.println("Algorithm not found");
            err.printStackTrace();
        }
        return rsaCipher;
    }

    /**
     * Creates an AES cipher for symmetric encryption to encrypt SealedObjects
     *
     * @param secretKey Symmetric secret key used in the AES cipher.
     * @return AES cipher generated with the secret key, in encrypt mode.
     * @throws NoSuchPaddingException   if the padding is wrong
     * @throws NoSuchAlgorithmException if the algorithm is wrong/does not exist
     * @throws InvalidKeyException      if the key is invalid
     */
    private Cipher createAESCipher(SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return aesCipher;
    }

    /**
     * Creates a secret key used for symmetric encryption.
     *
     * @return A new secret key
     * @throws NoSuchAlgorithmException if the algorithm is wrong/does not exist
     */
    private SecretKey createSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }
}
