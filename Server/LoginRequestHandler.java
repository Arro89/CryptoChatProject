package Server;

import CryptoClasses.DecryptionHandler;
import CryptoClasses.PasswordHandler;
import CryptoClasses.SignVerificationHandler;
import ObjectClasses.Request;

import javax.crypto.SealedObject;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * A handler of the server that is assigned to newly connected clients that have not yet logged in.
 * Handles both login and account creation requests on the behalf of the server. Every client is assigned
 * it's own LoginRequestHandler that it communicates with.
 *
 * @author Arvin Moshfegh
 * @version 1.0
 */
public class LoginRequestHandler implements Runnable {
    private Server server;
    private Socket clientSocket;
    private PublicKey clientPublicKey;
    private X509Certificate clientCertificate;
    private boolean waitingForLoginRequest;

    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;

    /**
     * Constructor of LoginRequestHandler. Creates a new objectOutputStream used to send the servers public key
     * to the client so it can be used for encrypting requests, and starts the thread.
     *
     * @param server       Server the LoginRequestHandler is connected to
     * @param clientSocket Clients socket.
     */
    public LoginRequestHandler(Server server, Socket clientSocket) {
        this.server = server;
        this.clientSocket = clientSocket;
        try {
            objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            objectOutputStream.writeObject(server.getEncryptionKey());
            objectOutputStream.writeObject(server.getCertificate());
            objectOutputStream.flush();
        } catch (IOException err) {
            System.err.println("Could not send object to client");
            err.printStackTrace();
        }
        waitingForLoginRequest = true;
        Thread thread = new Thread(this);
        thread.start();
    }

    /**
     * While the LoginRequestHandler is connected to the client trying to login, it will keep
     * reading requests sent by the client and tries to handle that request.
     * <p>
     * It reads the request type to determine what to do with it, gets the encrypted secret key bytes, the sealed object
     * and the clients public key.
     */
    @Override
    public void run() {
        while (waitingForLoginRequest) {
            try {
                System.out.println("waiting for object");
                objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
                String requestType = (String) objectInputStream.readObject();
                byte[] encryptedSecretKey = (byte[]) objectInputStream.readObject();
                SealedObject sealedObject = (SealedObject) objectInputStream.readObject();
                clientPublicKey = (PublicKey) objectInputStream.readObject();
                clientCertificate = (X509Certificate) objectInputStream.readObject();
                readRequest(requestType, encryptedSecretKey, sealedObject, clientCertificate);
            } catch (IOException | ClassNotFoundException err) {
                System.err.println("Could not read object from input stream");
                err.printStackTrace();
                stopThread();
            }
        }
    }


    /**
     * Reads the request by decrypting the message first to get the signed object, then verify the signature with the
     * clients certificate before extracting the request object.
     *
     * @param requestType        Type of request sent
     * @param encryptedSecretKey Symmetric secret key used to encrypt sealedObject
     * @param sealedObject       Object containing encrypted data
     * @param clientCertificate  Clients certificate
     */
    private void readRequest(String requestType, byte[] encryptedSecretKey, SealedObject sealedObject, X509Certificate clientCertificate) {
        try {
            DecryptionHandler decryptionHandler = new DecryptionHandler(server.getDecryptionKey());
            SignedObject signedObject = decryptionHandler.decryptSignedObject(encryptedSecretKey, sealedObject);
            SignVerificationHandler verificationHandler = new SignVerificationHandler(clientCertificate);
            Request request = (Request) verificationHandler.getSignedObjectContent(signedObject);
            handleRequest(requestType, request);
            System.out.println("USER CERT FIRST CONTACT -------> " + clientCertificate);
            byte[] certificateBytes = clientCertificate.getEncoded();
            System.out.println("INITIAL LOGIN BYTE LENGTH" + certificateBytes.length);
        } catch (InvalidKeyException err) {
            System.err.println("Could not create decryption handler with key");
            err.printStackTrace();
        } catch (IOException err) {
            System.out.println("Could not verify signature");
            err.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
    }

    /**
     * Handles the request depending on what type of request was sent. Either creates an account or logs in the user.
     *
     * @param requestType Request type sent by client (create account or login)
     * @param request     Request containing user credentials (username and password)
     */
    private void handleRequest(String requestType, Request request) {
        switch (requestType) {
            case ".createAccount" -> createAccount(request.getUsername(), request.getPassword());
            case ".login" -> loginUser(request.getUsername(), request.getPassword());
        }
    }

    /**
     * Tries to login the user by authenticating them first, before informing the client if it was successfully
     * authenticated or not. Sends a boolean value over the outputstream informing if the authentication was
     * successful (true) or not (false).
     *
     * @param username Clients username
     * @param password Clients password
     */
    private void loginUser(String username, char[] password) {
        boolean userAuthenticated = authenticateUser(username, password);
        if (userAuthenticated) {
            System.out.println("user authenticated");
            server.loginNewUser(username, clientPublicKey, clientSocket, clientCertificate);
            try {
                objectOutputStream.writeBoolean(true);
                objectOutputStream.writeObject(username);
                stopThread();
            } catch (IOException err) {
                System.err.println("Could not send verification to client");
                err.printStackTrace();
            }
        } else {
            try {
                System.out.println("write boolean");
                objectOutputStream.writeBoolean(false);
                objectOutputStream.writeObject(username);
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        }
    }

    /**
     * Initializes creation of a new account by hashing the password received from the user
     * and asking the server to store the username, hashed + salted password, and the salt used, in the database.
     *
     * @param username Clients requested username
     * @param password Clients requested password
     */
    private void createAccount(String username, char[] password) {
        PasswordHandler passwordHandler = new PasswordHandler(password);
        byte[] hashedPassword = passwordHandler.getHashedPassword();
        byte[] salt = passwordHandler.getSalt();
        server.registerNewUser(username, hashedPassword, salt, clientCertificate);
    }

    /**
     * Authenticates the user by getting the row from the database that corresponds to the clients username.
     * Hashes and salts the received password with same salt as previously used, and verifies if the received password
     * and stored password are the same.
     *
     * @param username The clients username
     * @param password The clients password
     * @return Boolean value if the password matched or not.
     */
    private boolean authenticateUser(String username, char[] password) {
        ResultSet resultSet = server.getUserInfoFromDatabase(username);
        boolean userAuthenticated = false;
        PasswordHandler passwordHandler = new PasswordHandler(password);
        byte[] storedPassword = null;
        byte[] storedSalt = null;
        try {
            while (resultSet.next()) {
                storedPassword = resultSet.getBytes("password");
                storedSalt = resultSet.getBytes("salt");
            }
        } catch (SQLException err) {
            System.err.println("Could not iterate through result set");
            err.printStackTrace();
        }
        boolean passwordVerified = passwordHandler.verifyPassword(storedPassword, storedSalt);
        if (passwordVerified) {
            userAuthenticated = true;
        }
        System.out.println("USER AUTHENTICATED: " + username + " " + userAuthenticated);
        return userAuthenticated;
    }


    /**
     * Stops the current thread by setting waitingForLoginRequest to false and closing the input+outputstream.
     */
    private void stopThread() {
        System.out.println("STOPPING LOGIN_REQUEST_HANDLER THREAD");
        waitingForLoginRequest = false;
    }
}
