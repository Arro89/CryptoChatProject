package ChatClient;

import CryptoClasses.DecryptionHandler;
import CryptoClasses.EncryptionHandler;
import CryptoClasses.SignHandler;
import CryptoClasses.SignVerificationHandler;
import ObjectClasses.Message;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.DialogPane;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

import javax.crypto.SealedObject;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Chat application that can communicate with other clients with encryption and signatures to ensure
 * integrity and confidentiality of the conversations. Uses SignedObject and SealedObject to communicate over unsecure
 * channels via a server.
 *
 * @author Arvin Moshfegh
 * @version 4.0
 */
public class ChatClient extends Application implements Runnable {
    private final String CSS_THEME = "DarkTheme.css";
    private Stage primaryStage;
    private ChatPane chatClientPane;
    private String username;
    private Socket socket;
    private boolean isRunning;
    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;

    private PrivateKey decryptionKey; //used for decrypting messages received
    private PrivateKey signatureKey; //Used to sign outgoing messages
    private PublicKey serverEncryptionKey; //used for encrypting messages sent to the server
    private X509Certificate serverCertificate; //used to verify servers messages


    /**
     * Method used to launch the program
     *
     * @param args User defined arguments
     */
    public static void main(String[] args) {
        launch(args);
    }

    /**
     * Start method for the ChatClient. Starts the JavaFX GUI, creates a login screen and shows it.
     *
     * @param primaryStage JavaFX stage component
     */
    @Override
    public void start(Stage primaryStage) {
        this.primaryStage = primaryStage;
        primaryStage.setTitle("ProgChat");
        primaryStage.addEventHandler(WindowEvent.WINDOW_CLOSE_REQUEST, new ExitHandler());
        createLoginScene();
        primaryStage.show();
    }

    /**
     * Run method. While the ChatClient thread is running it will keep listening for messages from the server and try to
     * read them.
     */
    @Override
    public void run() {
        while (isRunning) {
            try {
                objectInputStream = new ObjectInputStream(socket.getInputStream());
                byte[] encryptedSecretKey = (byte[]) objectInputStream.readObject();
                SealedObject sealedObject = (SealedObject) objectInputStream.readObject();
                readMessage(encryptedSecretKey, sealedObject);
            } catch (IOException | ClassNotFoundException err) {
                System.err.println("Could not read object from input stream");
                stopThread();
                err.printStackTrace();
            }
        }
    }

    /**
     * If the login handler has been authenticated by the server it will inform the chat client which can then
     * call the JavaFX thread to change screen to the chat (because a chat connection has been established).
     *
     * @param authenticated True if server accepted login request, false if not.
     */
    public void loginToChat(boolean authenticated) {
        if (authenticated) {
            Task<String> task = new Task<>() {
                @Override
                protected String call() throws Exception {
                    createChatScreen();
                    return null;
                }
            };
            Platform.runLater(task);
        }
    }

    /**
     * Method used to send messages to the server.
     *
     * @param message String containing message to be sent.
     */
    public void sendMessage(String message) {
        sendToServer(message);
    }

    /**
     * Get the current CSS file used as GUI theme.
     *
     * @return name of CSS file.
     */
    public String getTheme() {
        return CSS_THEME;
    }

    /**
     * Get the current JavaFX primaryStage used for the application. Can be used to open dialogs or windows in the app.
     *
     * @return current JavaFX primary stage.
     */
    public Stage getPrimaryStage() {
        return primaryStage;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Sets the current socket being used to communicate with the server.
     *
     * @param socket Socket connected to server.
     */
    public void setSocket(Socket socket) {
        this.socket = socket;
    }


    /**
     * Sets the key used to decrypt incoming messages from the server.
     *
     * @param decryptionKey Clients private RSA key
     */
    public void setDecryptionKey(PrivateKey decryptionKey) {
        this.decryptionKey = decryptionKey;
    }

    /**
     * Sets the key used to sign outgoing messages to the server.
     *
     * @param signatureKey Clients private DSA key
     */
    public void setSignatureKey(PrivateKey signatureKey) {
        this.signatureKey = signatureKey;
    }

    /**
     * Sets the servers key used to encrypt outgoing messages to the server.
     *
     * @param serverEncryptionKey Servers private RSA key.
     */
    public void setServerEncryptionKey(PublicKey serverEncryptionKey) {
        this.serverEncryptionKey = serverEncryptionKey;
    }

    /**
     * Sets the servers certificate used to verify the signature of incoming messages from the server.
     *
     * @param serverCertificate Servers X509 certificate
     */
    public void setServerCertificate(X509Certificate serverCertificate) {
        this.serverCertificate = serverCertificate;
    }

    /**
     * Sends a message to the server by creating a new message object, signing it and then sealing it, before
     * sending the encrypted symmetric key and SealedObject to the server.
     *
     * @param message String of message to be sent
     */
    private void sendToServer(String message) {
        try {
            Message messageObject = new Message(username, message);
            SignHandler signHandler = new SignHandler(signatureKey);
            SignedObject signedObject = signHandler.getSignedMessage(messageObject);
            EncryptionHandler encryptionHandler = new EncryptionHandler(serverEncryptionKey);
            SealedObject sealedObject = encryptionHandler.getSealedObject(signedObject);
            byte[] encryptedSecretKey = encryptionHandler.getEncryptedSecretKey();
            objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(encryptedSecretKey);
            objectOutputStream.writeObject(sealedObject);
            objectOutputStream.flush();
            System.out.println(messageObject.toString());
        } catch (InvalidKeyException err) {
            System.err.println("Cannot create encryption handler with said key");
            err.printStackTrace();
        } catch (IOException err) {
            System.err.println("Could not send object over output stream");
            err.printStackTrace();
        }
    }


    /**
     * Reads a message by decrypting the encrypted symmetric key, using the key to unlock the content with said symmetric
     * key and verifying the signature, before displaying it on the GUI.
     *
     * @param encryptedSecretKey Encrypted symmetric that sealed the object
     * @param sealedObject       SealedObject containing the signed message.
     */
    private void readMessage(byte[] encryptedSecretKey, SealedObject sealedObject) {
        try {
            DecryptionHandler decryptionHandler = new DecryptionHandler(decryptionKey);
            SignedObject signedObject = decryptionHandler.decryptSignedObject(encryptedSecretKey, sealedObject);
            SignVerificationHandler verificationHandler = new SignVerificationHandler(serverCertificate);
            Message message = (Message) verificationHandler.getSignedObjectContent(signedObject);
            chatClientPane.showMessage(getTimestamp(), message);
        } catch (InvalidKeyException err) {
            System.err.println("Cannot create decryption handler with said key");
            err.printStackTrace();
        } catch (IOException err) {
            System.err.println("Could not decrypt message");
            err.printStackTrace();
        }
    }

    /**
     * Gets the local timestamp of the current machine that ChatClient is running on.
     *
     * @return Returns a String of the local timestamp - formatted in hour/min/sec day/month/year
     */
    private String getTimestamp() {
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");
        LocalDateTime currentTime = LocalDateTime.now();
        return dateTimeFormatter.format(currentTime);
    }


    /**
     * Creates the login screen pane and shows it on the primary stage.
     */
    private void createLoginScene() {
        BorderPane loginPane = new LoginPane(this);
        Scene loginScene = new Scene(loginPane, 500, 400);
        loginPane.getStylesheets().add(CSS_THEME);
        primaryStage.setScene(loginScene);
        primaryStage.centerOnScreen();
    }

    /**
     * Creates the chat screen pane, shows it on the primary stage and starts a new thread for handling messages.
     */
    private void createChatScreen() {
        primaryStage.setTitle("ProgChat - " + username + " logged in.");
        chatClientPane = new ChatPane(this);
        Scene chatScene = new Scene(chatClientPane, 1000, 800);
        chatScene.getStylesheets().add(CSS_THEME);
        primaryStage.setScene(chatScene);
        primaryStage.centerOnScreen();
        isRunning = true;
        Thread thread = new Thread(this);
        thread.start();
    }

    /**
     * Creates an alert window if the client disconnects from the server while being logged in.
     */
    private void disconnectedAlert() {
        Task<String> task = new Task<>() {
            @Override
            protected String call() throws Exception {
                Alert alert = new Alert(Alert.AlertType.WARNING);
                alert.setTitle("Disconnected");
                alert.setContentText("Disconnected from server");
                alert.setHeaderText("");
                DialogPane dialogPane = alert.getDialogPane();
                dialogPane.getStylesheets().add(CSS_THEME);
                alert.showAndWait();
                return null;
            }
        };
        Platform.runLater(task);
    }

    /**
     * Stops the thread by setting isRunning to false and closing the input/output stream (which should close the socket
     * too according to documentation). Displays a disconnected alert.
     */
    private void stopThread() {
        isRunning = false;
        try {
            objectOutputStream.close();
            objectInputStream.close();
        } catch (IOException err) {
            System.err.println("Error closing input stream");
            err.printStackTrace();
        }
        disconnectedAlert();
    }

    /**
     * Inner handler class for dealing with closing the application when the window is closed.
     */
    private class ExitHandler implements EventHandler<WindowEvent> {
        @Override
        public void handle(WindowEvent event) {
            System.out.println("ExitHandler called");
            event.consume();
            Platform.exit();
            System.exit(0);
        }
    }
}