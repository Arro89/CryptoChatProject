package CryptoClasses;

import ObjectClasses.Message;
import ObjectClasses.Request;

import java.io.IOException;
import java.io.Serializable;
import java.security.*;

/**
 * Signature handler that handles the signing of data.
 * Can be used to either sign a request or sign a message to ensure the integrity of the data being transferred.
 *
 * @author Arvin Moshfegh
 * @version 3.0
 */
public class SignHandler {
    private PrivateKey signatureKey;

    /**
     * Constructor for the SignHandler. Saves the senders signature key (DSA Private Key) that is going to be used
     * for the signatures.
     *
     * @param signatureKey Senders DSA private key.
     */
    public SignHandler(PrivateKey signatureKey) {
        this.signatureKey = signatureKey;
    }

    /**
     * Gets a SignedObject containing a request that has been digitally signed.
     *
     * @param request Request object to be signed.
     * @return SignedObject containing the Request object.
     */
    public SignedObject getSignedRequest(Request request) {
        return createNewSignedObject(request);
    }

    /**
     * Gets a SignedObject containing a message that has been digitally signed.
     *
     * @param message Message object to be signed.
     * @return SignedObject containing the Request object.
     */
    public SignedObject getSignedMessage(Message message) {
        return createNewSignedObject(message);
    }

    /**
     * Method that creates a new SignedObject with any serializable object. Creates a new signature and uses
     * the signature key and the signature to sign the serializable object.
     *
     * @param serializableObject Any serializable object that is being signed.
     * @return SignedObject containing the signed data object.
     */
    private SignedObject createNewSignedObject(Serializable serializableObject) {
        SignedObject signedObject = null;
        try {
            Signature signature = Signature.getInstance("SHA256withDSA");
            signedObject = new SignedObject(serializableObject, signatureKey, signature);
        } catch (NoSuchAlgorithmException err) {
            System.err.println("Wrong algorithm for signature");
            err.printStackTrace();
        } catch (IOException err) {
            System.err.println("Could not create signed object");
            err.printStackTrace();
        } catch (SignatureException err) {
            System.err.println("");
            err.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return signedObject;
    }
}