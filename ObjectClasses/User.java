package ObjectClasses;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Class used to store user information in a single object for easier access and saving. The server can create these
 * objects so it can access the information it might need.
 *
 * @author Arvin Moshfegh
 * @version 2.0
 */
public class User {
    private String username;
    private PublicKey encryptionPublicKey;
    private X509Certificate certificate;

    /**
     * Constructor for User. Sets the users username, key for encryption and X509 certificate.
     *
     * @param username            Users username
     * @param encryptionPublicKey Public RSA key for encryption
     * @param certificate         X509Certificate for verification of digital signatures
     */
    public User(String username, PublicKey encryptionPublicKey, X509Certificate certificate) {
        this.username = username;
        this.encryptionPublicKey = encryptionPublicKey;
        this.certificate = certificate;
    }


    /**
     * Gets the users username.
     *
     * @return String of the username.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the public RSA key that can be used to encrypt messages that are being sent to the user.
     *
     * @return Public RSA key for encryption
     */
    public PublicKey getEncryptionPublicKey() {
        return encryptionPublicKey;
    }

    /**
     * Gets the X509 certificate containing DSA public key which can be used to verify digital signatures coming from
     * the private key connected to it.
     *
     * @return X509 certificate for verification of digital signatures
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Equals method so that two User objects can be compared to each other in a HashMap
     *
     * @param other other user object
     * @return true if it's the same user, false if it's not.
     */
    @Override
    public boolean equals(Object other) {
        if (other instanceof User) {
            User otherUser = (User) other;
            return username.equals(otherUser.username) && encryptionPublicKey.equals(otherUser.encryptionPublicKey);
        }
        return false;
    }

    /**
     * Creates a unique hash code for every User object.
     *
     * @return int of the hash code.
     */
    @Override
    public int hashCode() {
        return (int) (Math.random() * username.hashCode() * encryptionPublicKey.hashCode() * 3.14);
    }
}
