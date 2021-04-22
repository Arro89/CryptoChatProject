package Server;

import CryptoClasses.EncryptionHandler;
import CryptoClasses.SignHandler;
import ObjectClasses.Message;
import ObjectClasses.User;

import javax.crypto.SealedObject;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.sql.*;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * A server that handles encryption/decryption and signing/verification by being the intermediator between clients.
 * Clients who communicate with each other with send their messages to the server, who will ensure that it encrypts and
 * signs it so only authenticated clients will receive the messages.
 *
 * @author Arvin Moshfegh
 * @version 3.0
 */
public class Server implements Runnable {
    private ServerGUI serverGUI;
    private int port;
    private ServerSocket serverSocket;
    private Connection databaseConnection;
    private boolean isRunning;
    private String[] arguments;

    private PublicKey encryptionKey;
    private PrivateKey decryptionKey;

    private PrivateKey signatureKey;
    private Certificate certificate;

    private ArrayList<Socket> loginRequestList = new ArrayList<>();
    private HashMap<Socket, User> loggedInClientMap = new HashMap<>();

    /**
     * Constructor that creates the server. Connects it to the ServerGUI, loads the keypairs, creates a connection
     * to the database and starts the thread.
     *
     * @param serverGUI GUI that the server is displaying information on
     * @param args      Arguments consisting of location of keystore files, their aliases and passwords.
     */
    public Server(ServerGUI serverGUI, String[] args) {
        this.serverGUI = serverGUI;
        arguments = args;
        isRunning = true;
        port = 2000;
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException err) {
            System.err.println("Could not create server socket");
            stopThread();
            err.printStackTrace();
        }
        loadKeyPairFromKeyStore();
        connectToDatabase();
        updateAmountOfConnectedClients();
        Thread thread = new Thread(this);
        thread.start();
    }

    /**
     * Run method. While the thread is running the server will try to accept connecting clients and assigning them
     * a LoginRequestHandler.
     */
    @Override
    public void run() {
        while (isRunning) {
            try {
                Socket acceptedSocket = serverSocket.accept();
                addNewLoginRequestConnection(acceptedSocket);
            } catch (IOException err) {
                System.err.println("Failed to establish connection with client");
                err.printStackTrace();
            }
        }
    }

    /**
     * Registers a new user by adding their credentials to the database.
     *
     * @param username          Clients username
     * @param hashedPassword    Clients hashed and salted password
     * @param salt              Salt used for password
     * @param clientCertificate Clients X509 certificate.
     */
    public synchronized void registerNewUser(String username, byte[] hashedPassword, byte[] salt, X509Certificate clientCertificate) {
        addNewEntryInDatabase(username, hashedPassword, salt, clientCertificate);
    }

    /**
     * Logs in a new user by adding them to the new logged in client hashmap.
     *
     * @param username     Clients username
     * @param publicKey    Clients public key used for encryption
     * @param clientSocket Clients socket that they are connected via
     */
    public synchronized void loginNewUser(String username, PublicKey publicKey, Socket clientSocket, X509Certificate certificate) {
        addNewLoggedInClientToMap(username, publicKey, clientSocket, certificate);
    }


    /**
     * Gets users' info from the database for login authentication.
     *
     * @param username Username of the client who is being authenticated
     * @return Returns ResultSet containing user information.
     */
    public synchronized ResultSet getUserInfoFromDatabase(String username) {
        return getPasswordEntryFromDatabase(username);
    }

    /**
     * Removes a client from the server.
     *
     * @param user         User to be removed
     * @param clientSocket Users connected socket
     */
    public void removeClient(User user, Socket clientSocket) {
        removeLoggedInClientFromMap(user, clientSocket);
    }

    /**
     * Broadcasts a message by going through every connected client and sending a message individually to them.
     *
     * @param message Message to be sent
     */
    public synchronized void broadcastMessage(Message message) {
        for (Map.Entry<Socket, User> entry : loggedInClientMap.entrySet()) {
            Socket socket = entry.getKey();
            User user = entry.getValue();
            sendMessage(message, user, socket);
        }
        serverGUI.updateMessageArea(String.format("%s: new message broadcasted.", getTimestamp()));
    }

    /**
     * Sends a message to a specific user by signing and sealing the message before sending it out.
     * Encrypts the symmetric key for the sealed object with the receiving clients public RSA key, and signs the message
     * with the servers private RSA key.
     *
     * @param message Message containing text to be sent
     * @param user    Receiving user
     * @param socket  The clients socket its connected to
     */
    private void sendMessage(Message message, User user, Socket socket) {
        try {
            SignHandler signHandler = new SignHandler(signatureKey);
            SignedObject signedObject = signHandler.getSignedMessage(message);
            EncryptionHandler encryptionHandler = new EncryptionHandler(user.getEncryptionPublicKey());
            SealedObject sealedObject = encryptionHandler.getSealedObject(signedObject);
            byte[] encryptedSecretKey = encryptionHandler.getEncryptedSecretKey();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(encryptedSecretKey);
            objectOutputStream.writeObject(sealedObject);
            objectOutputStream.flush();
        } catch (IOException err) {
            System.err.println("Could not send message over output stream");
            err.printStackTrace();
        } catch (GeneralSecurityException err) {
            System.err.println("Error creating encryption handler");
            err.printStackTrace();
        }
    }

    /**
     * Adds a newly connected (but not logged in) client to a map of users' that the server is awaiting login requests
     * from. They are each provided their own LoginRequestHandler that handles the communication until the user is
     * logged in.
     *
     * @param acceptedSocket Clients socket that it is connected via
     */
    private void addNewLoginRequestConnection(Socket acceptedSocket) {
        System.out.println("new login requester added");
        loginRequestList.add(acceptedSocket);
        new LoginRequestHandler(this, acceptedSocket);
    }

    /**
     * Removes a logged in client from the server by removing it from the map containing logged in clients.
     *
     * @param user         User to be removed
     * @param clientSocket Socket to be removed
     */
    private void removeLoggedInClientFromMap(User user, Socket clientSocket) {
        loggedInClientMap.remove(clientSocket);
        serverGUI.updateMessageArea(String.format("%s: %s has disconnected.", getTimestamp(), user.getUsername()));
        updateAmountOfConnectedClients();
    }


    /**
     * Adds a newly logged in client to a map by creating a new User object with user information as a key and the value
     * is the socket it is connected with. Before adding the user it controls that the certificate that the logged in
     * user provided matches the one stored in the database, to ensure that the same signature is being used.
     *
     * @param username            Logged in clients username
     * @param publicKey           Clients public key for asymmetric encryption
     * @param clientSocket        Clients connected socket
     * @param providedCertificate the certificate provided by the user
     */
    private void addNewLoggedInClientToMap(String username, PublicKey publicKey, Socket clientSocket, X509Certificate providedCertificate) {
        loginRequestList.remove(clientSocket);
        X509Certificate userStoredCertificate = getUserCertificateFromDatabase(username);
        if (userStoredCertificate.equals(providedCertificate)) {
            User user = new User(username, publicKey, userStoredCertificate);
            loggedInClientMap.put(clientSocket, user);
            serverGUI.updateMessageArea(String.format("%s: %s has connected.", getTimestamp(), username));
            new ClientChatHandler(this, clientSocket, user);
            updateAmountOfConnectedClients();
        }
    }


    /**
     * Updates the amount of connected clients by calling on the server GUI to update the title.
     */
    private void updateAmountOfConnectedClients() {
        serverGUI.updateTitle(String.format("SERVER HOSTED ON: %s - PORT: %d - NR OF CONNECTED CLIENTS: %d",
                getServerSocketAddress(), port, loggedInClientMap.size()));
    }

    /**
     * Gets the server sockets host address.
     *
     * @return Host name of the server socket
     */
    private String getServerSocketAddress() {
        try {
            serverSocket.getInetAddress();
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException err) {
            System.err.println("Error getting host name");
            err.printStackTrace();
            return "error";
        }
    }

    /**
     * Connects to the database by creating a database connection.
     */
    private void connectToDatabase() {
        String databaseName = "";
        String username = ""; //removed
        String password = ""; //removed
        String computerName = "atlas.dsv.su.se";

        try {
            Class.forName("com.mysql.jdbc.Driver").getDeclaredConstructor().newInstance();
            String url = String.format("jdbc:mysql://%s/%s", computerName, databaseName);
            databaseConnection = DriverManager.getConnection(url, username, password);
        } catch (SQLException | ReflectiveOperationException err) {
            System.err.println("Could not connect to database");
            err.printStackTrace();
        }
        createTableIfNotExists();
    }


    /**
     * Gets the hashed password and salt from the database that belongs to a certain user.
     *
     * @param username Name of the user who's password is being retrieved
     * @return A ResultSet containing the password and salt
     */
    private ResultSet getPasswordEntryFromDatabase(String username) {
        ResultSet resultSet = null;
        String query = "SELECT password, salt FROM users WHERE username =?";
        try {
            PreparedStatement preparedStatement = databaseConnection.prepareStatement(query);
            preparedStatement.setString(1, username);
            resultSet = preparedStatement.executeQuery();
        } catch (SQLException err) {
            System.err.println("Could not create prepared statement");
            err.printStackTrace();
        }
        return resultSet;
    }

    /**
     * Method used to get a users certificate from the database. Gets the BLOB value from the database and calls on
     * supportive methods to create an X509 certificate.
     *
     * @param username Certificate holders username
     * @return X509Certificate from bytes
     */
    private X509Certificate getUserCertificateFromDatabase(String username) {
        byte[] certificateBytes = null;
        String query = "SELECT certificate FROM users WHERE username =?";
        try {
            PreparedStatement preparedStatement = databaseConnection.prepareStatement(query);
            preparedStatement.setString(1, username);
            ResultSet resultSet = preparedStatement.executeQuery();
            while (resultSet.next()) {
                certificateBytes = resultSet.getBytes("certificate");
                System.out.println("CERTIFICATE BYTE LENGTH" + certificateBytes.length);
            }
        } catch (SQLException err) {
            System.err.println("Could not retrieve certificate from database");
            err.printStackTrace();
        }
        return transformBytesToCertificate(certificateBytes);
    }

    /**
     * Method that transforms a byte array of a certificate to an X509 certificate object in Java. Can be used
     * to retrieve a Certificate saved in the database
     *
     * @param certificateBytes Bytes of the X509 certificate.
     * @return X509Certificate from bytes
     */
    private X509Certificate transformBytesToCertificate(byte[] certificateBytes) {
        X509Certificate x509Certificate = null;
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            x509Certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));

        } catch (CertificateException err) {
            System.err.println("Could not get instance of certificate");
            err.printStackTrace();
        }
        return x509Certificate;
    }


    /**
     * Adds a newly registered user in the database. Uses a prepared statement to add all values and saves the
     * username, password, salt and certificate. Converts the certificate to bytes before storage.
     *
     * @param username          Clients username
     * @param hashedPassword    Hashed and salted password as bytes
     * @param salt              salt as bytes
     * @param clientCertificate X509 certificate
     */
    private void addNewEntryInDatabase(String username, byte[] hashedPassword, byte[] salt, X509Certificate clientCertificate) {
        String query = "INSERT INTO users (username, password, salt, certificate) VALUES (?, ?, ?, ?)";
        try {
            PreparedStatement preparedStatement = databaseConnection.prepareStatement(query);
            byte[] certificateByte = clientCertificate.getEncoded();
            preparedStatement.setString(1, username);
            preparedStatement.setBytes(2, hashedPassword);
            preparedStatement.setBytes(3, salt);
            preparedStatement.setBytes(4, certificateByte);
            preparedStatement.execute();
        } catch (SQLException err) {
            System.err.println("Could not add user to database");
            err.printStackTrace();
        } catch (CertificateEncodingException err) {
            System.err.println("Could not get certificates bytes");
            err.printStackTrace();
        }
    }

    /**
     * If a table does not exist in the database this method will generate a new one with the fields
     * username, password, salt and certificate.
     */
    private void createTableIfNotExists() {
        try {
            Statement statement = databaseConnection.createStatement();
            String createTableQuery = "CREATE TABLE IF NOT EXISTS users"
                    + "(id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,"
                    + "username TEXT(30),"
                    + "password BLOB,"
                    + "salt BLOB,"
                    + "certificate LONGBLOB)";
            statement.executeUpdate(createTableQuery);
            System.out.println("Table created");
        } catch (SQLException err) {
            System.err.println("Error creating table");
            err.printStackTrace();
        }
    }

    /**
     * Loads both keypairs from keystore and saves them so the server can keep track of its encryption/decryption
     * key-pair and signature keypair.
     */
    private void loadKeyPairFromKeyStore() {
        String rsaKeyStoreFile = arguments[0];
        String rsaKeyStoreAlias = arguments[1];
        char[] rsaKeyStorePassword = arguments[2].toCharArray();
        char[] rsaKeyPassword = arguments[3].toCharArray();

        String dsaKeyStoreFile = arguments[4];
        String dsaKeyStoreAlias = arguments[5];
        char[] dsaKeyStorePassword = arguments[6].toCharArray();
        char[] dsaKeyPassword = arguments[7].toCharArray();

        try {
            FileInputStream rsaInputStream = new FileInputStream(rsaKeyStoreFile);
            KeyStore rsaKeyStore = KeyStore.getInstance("JKS");
            rsaKeyStore.load(rsaInputStream, rsaKeyStorePassword);
            decryptionKey = (PrivateKey) rsaKeyStore.getKey(rsaKeyStoreAlias, rsaKeyPassword);
            encryptionKey = rsaKeyStore.getCertificate(rsaKeyStoreAlias).getPublicKey();
            FileInputStream dsaInputStream = new FileInputStream(dsaKeyStoreFile);
            KeyStore dsaKeyStore = KeyStore.getInstance("JKS");
            dsaKeyStore.load(dsaInputStream, dsaKeyStorePassword);
            signatureKey = (PrivateKey) dsaKeyStore.getKey(dsaKeyStoreAlias, dsaKeyPassword);
            certificate = dsaKeyStore.getCertificate(dsaKeyStoreAlias);
        } catch (IOException err) {
            System.err.println("Could not load keystore");
            err.printStackTrace();
        } catch (GeneralSecurityException err) {
            System.err.println("Error generated when loading keys from keystore");
            err.printStackTrace();
        }
    }

    /**
     * Used to get the public key from the encryption keypair. Other clients can use this key to seal messages
     * that they want to send to the server.
     *
     * @return public RSA encryption key.
     */
    protected synchronized PublicKey getEncryptionKey() {
        return encryptionKey;
    }

    /**
     * Used to get the private key from the encryption keypair. This key can be used to decrypt messages
     * signed with the public key.
     *
     * @return private RSA decryption key.
     */
    protected synchronized PrivateKey getDecryptionKey() {
        return decryptionKey;
    }

    /**
     * Used to get the servers current X509 certificate being used.
     *
     * @return X509 certificate of the server.
     */
    protected synchronized Certificate getCertificate() {
        return certificate;
    }

    /**
     * Gets the local timestamp.
     *
     * @return Returns a String of the local timestamp - formatted in hour:min:seconds.
     */
    private String getTimestamp() {
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");
        LocalDateTime currentTime = LocalDateTime.now();
        return dateTimeFormatter.format(currentTime);
    }

    /**
     * Stops the server thread and closes the server socket.
     */
    private void stopThread() {
        System.out.println("Closing server called");
        isRunning = false;
        try {
            serverSocket.close();
        } catch (IOException err) {
            System.err.println("Error when closing server socket");
            err.printStackTrace();
        }
        System.exit(1);
    }
}