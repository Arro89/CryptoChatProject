package CryptoClasses;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Class that handles passwords. It can both hash passwords with newly created salt, or use previous salt
 * to hash a password before comparing it to another password that has been salted and hashed.
 *
 * @author Arvin Moshfegh
 * @version 1.0
 */

public class PasswordHandler {
    private char[] receivedPassword;
    private byte[] salt;

    /**
     * Constructor for password handler that takes the received password and creates new salt for easier
     * hashing.
     *
     * @param receivedPassword Password being handled by the class.
     */
    public PasswordHandler(char[] receivedPassword) {
        this.receivedPassword = receivedPassword;
        this.salt = generateNewSalt();
    }

    /**
     * Creates a newly hashed and salted password.
     *
     * @return The hashed and salted password
     */
    public byte[] getHashedPassword() {
        return hashPassword(this.salt);
    }

    /**
     * Returns the salt of this PasswordHandler instance that was created with the constructor.
     *
     * @return 16 byte salt.
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Compares and verifies passwords by comparing a previously hashed and salted password with a
     * newly received password. It uses the previously used salt to hash and salt the new password
     * and checks if it matches the expected password.
     *
     * @param expectedPassword Previously saved password
     * @param storedSalt       Salt previously used to hash the password
     * @return true if passwords match, false if they do not match.
     */
    public boolean verifyPassword(byte[] expectedPassword, byte[] storedSalt) {
        byte[] receivedPassword = hashPassword(storedSalt);
        return Arrays.equals(receivedPassword, expectedPassword);
    }

    /**
     * Hashes a password with salt to ensure that even two people who use the same password cannot
     * generate the exact same hash.
     *
     * @param salt salt used to salt the password to make it more unique.
     * @return Returns bytes of the hashed password.
     */
    private byte[] hashPassword(byte[] salt) {
        byte[] hashedPassword = null;
        try {
            KeySpec spec = new PBEKeySpec(receivedPassword, salt, 1000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            hashedPassword = factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException err) {
            System.err.println("Algorithm not found");
            err.printStackTrace();
        } catch (InvalidKeySpecException err) {
            System.err.println("Invalid keyspec");
            err.printStackTrace();
        }
        return hashedPassword;
    }

    /**
     * Creates new salt by using SecureRandom.
     *
     * @return Newly created salt.
     */
    private byte[] generateNewSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }
}
