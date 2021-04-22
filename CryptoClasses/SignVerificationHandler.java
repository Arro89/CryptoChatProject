package CryptoClasses;

import ObjectClasses.Message;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;

/**
 * Signature verification handler that handles verification of signatures and helps extracting content from the signed
 * objects.
 *
 * @author Arvin Moshfegh
 * @version 3.0
 */
public class SignVerificationHandler {
    private X509Certificate certificate;

    /**
     * Constructor for the handler - saves the senders certificate so it can be used for future verification.
     *
     * @param certificate Certificate of the sender to verify the signature
     */
    public SignVerificationHandler(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Returns the content inside the signed object.
     *
     * @param signedObject SignedObject to be verified
     * @return Content of the signed object as an Object type. Needs to be casted at retrieval
     * @throws IOException If the content in the signed object could not be extracted
     */
    public Object getSignedObjectContent(SignedObject signedObject) throws IOException {
        return verifySignature(signedObject);
    }

    /**
     * Verifies the signature of an object before extracting
     *
     * @param signedObject SignedObject to be verified
     * @return Object that was inside the SignedObject.
     * @throws IOException If the signature could not be verified to extract the content
     */
    private Object verifySignature(SignedObject signedObject) throws IOException {
        Object verifiedObject = null;
        try {
            Signature signature = Signature.getInstance("SHA256withDSA");
            signature.initVerify(certificate);
            if (signedObject.verify(certificate.getPublicKey(), signature)) {
                System.out.println("SIGNATURE VERIFIED");
                verifiedObject = signedObject.getObject();
            } else {
                verifiedObject = new Message("SERVER", "USERS MESSAGE COULD NOT BE VERIFIED\n");
            }
        } catch (NoSuchAlgorithmException err) {
            System.err.println("Wrong algorithm for signature");
            err.printStackTrace();
        } catch (InvalidKeyException err) {
            System.err.println("Invalid certificate public key");
            err.printStackTrace();
        } catch (SignatureException err) {
            System.err.println("Could not verify with certificate public key");
            err.printStackTrace();
        } catch (ClassNotFoundException err) {
            System.err.println("Class not found");
            err.printStackTrace();
        }
        return verifiedObject;
    }
}