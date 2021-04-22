package ChatClient;

import CryptoClasses.EncryptionHandler;
import CryptoClasses.SignHandler;
import ObjectClasses.Request;

import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.X509Certificate;

/**
 * LoginHandler that handles the login communication with the servers LoginRequestHandler.
 *
 * @author Arvin Moshfegh
 * @version 4.0
 */
public class LoginHandler implements Runnable {
    private ChatClient chatClient;
    private LoginPane loginPane;

    private Socket socket;
    private String hostAddress;
    private int port;
    private ObjectInputStream objectInputStream;
    private boolean awaitingLogin;

    private PublicKey encryptionKey;
    private PrivateKey decryptionKey;
    private PrivateKey signatureKey;
    private X509Certificate myCertificate;
    private PublicKey serverEncryptionKey;
    private X509Certificate serverCertificate;

    /**
     * Constructor for LoginHandler. Sets the chatClient it is connected to, but also the LoginPane that handles the
     * login GUI. Creates the initial connection to the server.
     *
     * @param chatClient ChatClient it is connected to.
     * @param loginPane  GUI Pane it is communicating via.
     */
    public LoginHandler(ChatClient chatClient, LoginPane loginPane) {
        this.chatClient = chatClient;
        this.loginPane = loginPane;
        hostAddress = "127.0.0.1";
        port = 2000;
        connectToServer();
        awaitingLogin = true;
        Thread thread = new Thread(this);
        thread.start();
    }

    /**
     * Run method. While the LoginHandler is awaiting login authentication it will keep listening to a boolean value
     * and what username that has been authenticated. If the server fails to log in a user it can keep waiting for
     * new responses and send new requests.
     */
    @Override
    public void run() {
        while (awaitingLogin) {
            System.out.println("Waiting for approval from server");
            try {
                boolean authenticated = objectInputStream.readBoolean();
                String username = (String) objectInputStream.readObject();
                if (authenticated) {
                    loginUser(username);
                } else {
                    loginPane.alertLoginFailed();
                }
            } catch (IOException | ClassNotFoundException err) {
                System.err.println("Could not read from input stream");
                err.printStackTrace();
                loginPane.alertConnectionFailure();
                stopThread();
            }
        }
    }

    /**
     * Checks that the decryption key and signature key is not null before allowing to encrypt and send
     * a message. If these two keys are null, then clearly there has been an failed attempt to upload the keys
     * because either alias or password is not correct or the keys have not been uploaded for any other reason,
     * hence a safe connection cannot be established. Both key-pairs have to be successfully loaded for the secure
     * connection to be established.
     *
     * @param requestType The kind of request being sent (either login or account creation request)
     * @param request     Request object being sent to server.
     */
    public void sendRequest(String requestType, Request request) {
        if (decryptionKey != null && signatureKey != null) {
            sendToServer(requestType, request);
        }
    }

    /**
     * Method used to store the key pairs from the keystores selected in the LoginPane GUI.
     *
     * @param typeOfKeyStore   Type of keystore being used
     * @param keyStoreFile     Location of the keystore file
     * @param alias            Alias of the keystore holder
     * @param keyStorePassword Password to the keystore
     * @param keyPassword      Password to the key
     */
    public void setKeyStorePair(String typeOfKeyStore, File keyStoreFile, String alias,
                                char[] keyStorePassword, char[] keyPassword) {
        trySettingKeyPair(typeOfKeyStore, keyStoreFile, alias, keyStorePassword, keyPassword);
    }


    /**
     * Connects to the server by creating a new socket with the host address and port. Upon first connection
     * it will send over its public key and certificate so the encrypted and signed communication can begin.
     */
    private void connectToServer() {
        System.out.println("connect to server");
        try {
            socket = new Socket(hostAddress, port);
            objectInputStream = new ObjectInputStream(socket.getInputStream());
            serverEncryptionKey = (PublicKey) objectInputStream.readObject();
            serverCertificate = (X509Certificate) objectInputStream.readObject();
        } catch (UnknownHostException err) {
            System.err.println("Could not connect");
            err.printStackTrace();
            stopThread();
        } catch (IOException err) {
            System.err.println("Error creating new socket/inputStream or reading object from inputStream");
            loginPane.alertConnectionFailure();
            stopThread();
            err.printStackTrace();
        } catch (ClassNotFoundException err) {
            System.err.println("Could not retrieve servers public key");
            err.printStackTrace();
        }
    }

    /**
     * Method used to login a user by setting the correct encryption and signature keys in the chatClient and what
     * socket is being used for communication, before asking the ChatClient GUI to change screen.
     * Stops the current LoginHandler thread as it is no longer needed.
     *
     * @param username Username of user that was authenticated.
     */
    private void loginUser(String username) {
        chatClient.setDecryptionKey(decryptionKey);
        chatClient.setSignatureKey(signatureKey);
        chatClient.setServerEncryptionKey(serverEncryptionKey);
        chatClient.setServerCertificate(serverCertificate);
        chatClient.setUsername(username);
        chatClient.setSocket(socket);
        chatClient.loginToChat(true);
        stopThread();
    }

    /**
     * Sends the request to the server by first signing it with clients private DSA key, then creating a
     * sealed object containing the signed request. Sends the request type, symmetric key used to seal the
     * request, the encrypted content and also provides the server with clients' public RSA key and certificate
     * for future encrypted and signed communication.
     *
     * @param requestType Type of request the client is sending (Login or account creation)
     * @param request     Request object containing the clients credentials
     */
    private void sendToServer(String requestType, Request request) {
        try {
            SignHandler signHandler = new SignHandler(signatureKey);
            SignedObject signedObject = signHandler.getSignedRequest(request);
            EncryptionHandler encryptionHandler = new EncryptionHandler(serverEncryptionKey);
            SealedObject sealedObject = encryptionHandler.getSealedObject(signedObject);
            byte[] encryptedSecretKey = encryptionHandler.getEncryptedSecretKey();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(requestType);
            objectOutputStream.writeObject(encryptedSecretKey);
            objectOutputStream.writeObject(sealedObject);
            objectOutputStream.writeObject(encryptionKey);
            objectOutputStream.writeObject(myCertificate);
            objectOutputStream.flush();
        } catch (InvalidKeyException err) {
            System.err.println("Could not create encryption handler with the key");
            err.printStackTrace();
        } catch (IOException err) {
            System.err.println("Could not send sealed object");
            err.printStackTrace();
        }
    }

    /**
     * Method used to set the key pairs. Depending on what type of keystore it is dealing with, it will determine
     * what variables it will save the private key and public key/certificate.
     *
     * @param typeOfKeyStore   Keystore type (if its encryption/decryption or signature pair)
     * @param keyStoreFile     Location of keystore file
     * @param alias            Alias of the keystore holder
     * @param keyStorePassword Password to the keystore
     * @param keyPassword      Password to the key
     */
    private void trySettingKeyPair(String typeOfKeyStore, File keyStoreFile, String alias, char[] keyStorePassword, char[] keyPassword) {
        try {
            FileInputStream fileInputStream = new FileInputStream(keyStoreFile);
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(fileInputStream, keyStorePassword);
            switch (typeOfKeyStore) {
                case "encryption":
                    decryptionKey = (PrivateKey) keyStore.getKey(alias, keyPassword);
                    encryptionKey = keyStore.getCertificate(alias).getPublicKey();
                case "signature":
                    signatureKey = (PrivateKey) keyStore.getKey(alias, keyPassword);
                    myCertificate = (X509Certificate) keyStore.getCertificate(alias);
            }
        } catch (GeneralSecurityException err) {
            System.err.println("Error with the keystore");
            loginPane.alertLoginFailed();
            err.printStackTrace();
        } catch (IOException err) {
            System.err.println("Could not load file");
            loginPane.alertLoginFailed();
            err.printStackTrace();
        }
    }

    /**
     * Stops the thread by setting awaitingLogin to false. Does not stop the input/output streams as this will also
     * cause the socket connection to close when user is logged in.
     */
    private void stopThread() {
        awaitingLogin = false;
    }
}
