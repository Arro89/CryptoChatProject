package Server;

import CryptoClasses.DecryptionHandler;
import CryptoClasses.SignVerificationHandler;
import ObjectClasses.Message;
import ObjectClasses.User;

import javax.crypto.SealedObject;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.SignedObject;

/**
 * Class that handles the chat client. It keeps listening for incoming messages and tells the server to broadcast any
 * message that has been decrypted and whose signature has been verified.
 *
 * @author Arvin Moshfegh
 * @version 3.0
 */
public class ClientChatHandler implements Runnable {
    private Server server;
    private Socket clientSocket;
    private User user;

    private boolean waitingForMessage = true;


    /**
     * Constructor. Sets the server the ClientHandler is connected to, the socket of the client and what user it is
     * assigned to. Starts the
     *
     * @param server       Server it is connected to
     * @param clientSocket Client it is handling
     * @param user         User object of the client its handling
     */
    public ClientChatHandler(Server server, Socket clientSocket, User user) {
        this.server = server;
        this.clientSocket = clientSocket;
        this.user = user;
        Thread thread = new Thread(this);
        thread.start();
        System.out.println("New client handler created for " + user.getUsername());
    }

    /**
     * Run method. While the ClientHandler is waiting for messages it will keep reading encrypted symmetric keys
     * and SealedObjects before forwarding it to the Server for broadcasting.
     */
    @Override
    public void run() {
        while (waitingForMessage) {
            try {
                ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
                byte[] encryptedSecretKeyBytes = (byte[]) objectInputStream.readObject();
                SealedObject sealedObject = (SealedObject) objectInputStream.readObject();
                System.out.println(sealedObject);
                forwardMessage(encryptedSecretKeyBytes, sealedObject);
                System.out.println("FORWARD MESSAGE");
            } catch (IOException | ClassNotFoundException err) {
                System.err.println("Could not read object from input stream");
                err.printStackTrace();
                stopThread();
            }
        }
    }

    /**
     * Prepares the received message for forwarding and broadcasting to other clients by decrypting it, verifying
     * the signature of the message and then calling on the server to broadcast it to all connected clients.
     *
     * @param encryptedSecretKeyBytes Symmetric encrypted key used when sealing the object
     * @param sealedObject            SealedObject containing the message.
     */
    private void forwardMessage(byte[] encryptedSecretKeyBytes, SealedObject sealedObject) {
        try {
            DecryptionHandler decryptionHandler = new DecryptionHandler(server.getDecryptionKey());
            SignedObject signedObject = decryptionHandler.decryptSignedObject(encryptedSecretKeyBytes, sealedObject);
            SignVerificationHandler verificationHandler = new SignVerificationHandler(user.getCertificate());
            Message message = (Message) verificationHandler.getSignedObjectContent(signedObject);
            server.broadcastMessage(message);
        } catch (GeneralSecurityException err) {
            System.err.println("Could not create decryption handler");
            err.printStackTrace();
        } catch (IOException err) {
            System.err.println("Could not decrypt message");
            err.printStackTrace();
        }
    }

    /**
     * Stops the thread by setting waitingForMessage to false and calling on the server to remove the client from map of
     * logged in users.
     */
    private void stopThread() {
        System.out.println("STOPPING CHAT_HANDLER THREAD");
        waitingForMessage = false;
        server.removeClient(user, clientSocket);
    }

}
