package ChatClient;

import ObjectClasses.Request;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.stage.FileChooser;

import java.io.File;
import java.util.Arrays;
import java.util.List;

/**
 * Graphical component for ChatClient. Displays the login screen used for login and account creation.
 *
 * @author Arvin Moshfegh
 * @version 1.0
 */
public class LoginPane extends BorderPane {
    private ChatClient chatClient;
    private LoginHandler loginHandler;

    private TextField usernameField;
    private PasswordField passwordField;

    private TextField encryptionAlias;
    private PasswordField encryptionStorePassword;
    private PasswordField encryptionPassword;

    private TextField signatureAlias;
    private PasswordField signatureStorePassword;
    private PasswordField signaturePassword;

    private CheckBox encryptionFileCheckBox;
    private CheckBox signatureFileCheckBox;

    private Button encryptionPairButton;
    private Button signingPairButton;
    private Button loginButton;
    private Button createAccountButton;

    private GridPane gridPane;
    private HBox buttonBox;

    private File encryptionFile;
    private File signatureFile;

    /**
     * Constructor for the LoginPane GUI. Saves the chatclient it is conneted to and creates all neccessary UI nodes
     * before creating a new login handler to deal with login requests.
     *
     * @param chatClient Current ChatClient
     */
    public LoginPane(ChatClient chatClient) {
        this.chatClient = chatClient;
        createGuiNodes();
        setupButtonBox();
        setUpGridPane();
        this.setCenter(gridPane);
        this.setBottom(buttonBox);

        loginHandler = new LoginHandler(this.chatClient, this);
    }


    /**
     * Method that handles both login and account creation requests. When all information is filled out it will
     * ask the loginHandler to try to store the key pairs and inform that the user wants to send a request to the server.
     *
     * @param requestType The type of request the user is making. ".login" or ".createAccount" is sent to loginhandler.
     */
    private void handleButtonRequest(String requestType) {
        if (credentialsFilledOut()) {
            Request request = new Request(usernameField.getText(), passwordField.getText().toCharArray());
            loginHandler.setKeyStorePair("encryption", encryptionFile, encryptionAlias.getText(),
                    encryptionStorePassword.getText().toCharArray(), encryptionPassword.getText().toCharArray());

            loginHandler.setKeyStorePair("signature", signatureFile, signatureAlias.getText(),
                    signatureStorePassword.getText().toCharArray(), signaturePassword.getText().toCharArray());

            loginHandler.sendRequest(requestType, request);
            if (requestType.equals(".createAccount")) {
                alertAccountCreated();
            }
        }
    }


    /**
     * Opens a FileChooser window so the user can pick the JKS keystore that is going to be used for signature/encryption.
     *
     * @param typeOfFile Type of file being uploaded to determine what key to upload
     */
    private void chooseFile(String typeOfFile) {
        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter fileFilter = new FileChooser.ExtensionFilter("KeyStore File", "*.jks");
        fileChooser.getExtensionFilters().addAll(fileFilter);
        File file = fileChooser.showOpenDialog(chatClient.getPrimaryStage());
        if (file != null) {
            switch (typeOfFile) {
                case ".encryptionFile" -> loadEncryptionKeyPair(file);
                case ".signatureFile" -> loadSignatureKeyPair(file);
            }
        }
    }

    /**
     * Saves the encryption keypair file and marks the checkbox to inform that it has been picked.
     *
     * @param file File to be saved
     */
    private void loadEncryptionKeyPair(File file) {
        encryptionFile = file;
        setCheckBoxMarked(encryptionFileCheckBox);
    }

    /**
     * Saves the signature keypair file and marks the checkbox to inform that it has been picked.
     *
     * @param file File to be saved
     */
    private void loadSignatureKeyPair(File file) {
        signatureFile = file;
        setCheckBoxMarked(signatureFileCheckBox);
    }

    /**
     * Checks if all credentials are filled out. Checks if both key-pairs are uploaded and all fields are filled out.
     *
     * @return Return true if everything needed filled out, false if anything is missing
     */
    private boolean credentialsFilledOut() {
        return allFieldsFilledOut() && keyPairsUploaded();
    }

    /**
     * Checks if the key-pair files are uploaded.
     *
     * @return Returns true if both files are uploaded, false if one or both are not.
     */
    private boolean keyPairsUploaded() {
        if (encryptionFileCheckBox.isSelected() && signatureFileCheckBox.isSelected()) {
            return true;
        }
        alertKeyPairNotUploaded();
        return false;
    }

    /**
     * Checks if all the input fields are filled out
     *
     * @return False if there are empty fields, true if no field is empty
     */
    private boolean allFieldsFilledOut() {
        if (usernameField.getText().isBlank() || usernameField.getText().isEmpty()
                || passwordField.getText().isEmpty() || passwordField.getText().isBlank()
                || encryptionAlias.getText().isEmpty() || encryptionAlias.getText().isBlank()
                || encryptionStorePassword.getText().isEmpty() || encryptionStorePassword.getText().isBlank()
                || encryptionPassword.getText().isEmpty() || encryptionPassword.getText().isBlank()
                || signatureAlias.getText().isEmpty() || signatureAlias.getText().isBlank()
                || signaturePassword.getText().isEmpty() || signatureStorePassword.getText().isBlank()
                || signaturePassword.getText().isEmpty() || signaturePassword.getText().isBlank()) {
            alertEmptyField();
            return false;
        }
        return true;
    }


    /**
     * Creates an alert window to be shown.
     *
     * @param title       String with title of the alert window
     * @param contentText String with content of the alert window
     * @param alertType   Type of alert window (warning/information/etc)
     */
    private void createAlertWindow(String title, String contentText, Alert.AlertType alertType) {
        Task<String> task = new Task<>() {
            @Override
            protected String call() throws Exception {
                Alert alert = new Alert(alertType);
                alert.setTitle(title);
                alert.setContentText(contentText);
                alert.setHeaderText("");
                setDialogPaneTheme(alert);
                alert.showAndWait();
                return null;
            }
        };
        Platform.runLater(task);
    }


    /**
     * Method that informs user that the login failed for some reason
     */
    public void alertLoginFailed() {
        String title = "Login failed";
        String contentText = "Could not login. Please provide correct credentials for login and keystore.";
        Alert.AlertType alertType = Alert.AlertType.WARNING;
        createAlertWindow(title, contentText, alertType);
        clearPasswordFields();
    }

    /**
     * Method used to inform user of connection failure.
     */
    public void alertConnectionFailure() {
        String title = "No connection";
        String contextText = "Could not establish connection to the server";
        Alert.AlertType alertType = Alert.AlertType.INFORMATION;
        createAlertWindow(title, contextText, alertType);
        clearPasswordFields();
    }

    /**
     * Method that informs user that the account has been created.
     */
    private void alertAccountCreated() {
        String title = "Account Created";
        String contentText = "Account successfully created.\n\nYou can now login";
        Alert.AlertType alertType = Alert.AlertType.INFORMATION;
        createAlertWindow(title, contentText, alertType);
    }


    /**
     * Method that informs user that one or more fields are empty.
     */
    private void alertEmptyField() {
        String title = "ERROR";
        String contentText = "Please fill in all your credentials";
        Alert.AlertType alertType = Alert.AlertType.WARNING;
        createAlertWindow(title, contentText, alertType);
    }

    /**
     * Method that informs user that key pair files have not been uploaded
     */
    private void alertKeyPairNotUploaded() {
        String title = "ERROR";
        String contentText = "Please pick your .JKS keystore for both encryption and signing";
        Alert.AlertType alertType = Alert.AlertType.WARNING;
        createAlertWindow(title, contentText, alertType);
    }

    /**
     * Changes the theme of the alert window to match the Chat application UI
     *
     * @param alert Alert window to be customized
     */
    private void setDialogPaneTheme(Alert alert) {
        DialogPane dialogPane = alert.getDialogPane();
        dialogPane.getStylesheets().add(chatClient.getTheme());
    }

    /**
     * Changes the checkboxes to clarify when a file has been picked.
     *
     * @param checkBox Checkbox to be checked.
     */
    private void setCheckBoxMarked(CheckBox checkBox) {
        checkBox.setSelected(true);
        checkBox.getStylesheets().add(chatClient.getTheme());
    }

    /**
     * Clears the passwords fields.
     */
    private void clearPasswordFields() {
        passwordField.clear();
        encryptionStorePassword.clear();
        encryptionPassword.clear();
        signatureStorePassword.clear();
        signaturePassword.clear();
    }

    /**
     * Formats all TextFields by setting the width to 200 and height to 20.
     */
    private void setTextFieldFormat() {
        List<TextField> listOfTextFields = Arrays.asList(
                usernameField, passwordField,
                encryptionStorePassword, encryptionPassword);
        for (TextField textField : listOfTextFields) {
            textField.setPrefWidth(200);
            textField.setPrefHeight(20);
        }
    }

    /**
     * Creates the GUI nodes so they are available for placing on the BorderPane.
     */
    private void createGuiNodes() {
        usernameField = new TextField();
        passwordField = new PasswordField();
        encryptionAlias = new TextField();
        encryptionStorePassword = new PasswordField();
        encryptionPassword = new PasswordField();
        signatureAlias = new TextField();
        signatureStorePassword = new PasswordField();
        signaturePassword = new PasswordField();
        setTextFieldFormat();

        encryptionPairButton = new Button("Choose File");
        encryptionPairButton.setOnAction(e -> chooseFile(".encryptionFile"));

        signingPairButton = new Button("Choose File");
        signingPairButton.setOnAction(e -> chooseFile(".signatureFile"));

        loginButton = new Button("Login");
        loginButton.setOnAction(e -> handleButtonRequest(".login"));

        createAccountButton = new Button("Create Account");
        createAccountButton.setOnAction(e -> handleButtonRequest(".createAccount"));

        encryptionFileCheckBox = new CheckBox();
        signatureFileCheckBox = new CheckBox();
        encryptionFileCheckBox.setDisable(true);
        signatureFileCheckBox.setDisable(true);

        gridPane = new GridPane();
        buttonBox = new HBox();
    }

    /**
     * Sets up the buttonBox with new HBoxes containing the login and create account button.
     * Used to ensure that they are evenly spaced and placed on each corner of the buttonBox.
     */
    private void setupButtonBox() {
        HBox leftBox = new HBox();
        leftBox.getChildren().add(loginButton);
        leftBox.setAlignment(Pos.CENTER);
        HBox.setHgrow(leftBox, Priority.ALWAYS);

        HBox rightBox = new HBox();
        rightBox.getChildren().add(createAccountButton);
        rightBox.setAlignment(Pos.CENTER);
        HBox.setHgrow(rightBox, Priority.ALWAYS);

        buttonBox.getChildren().addAll(leftBox, rightBox);
    }

    /**
     * Sets up the gridPane containing all nodes shown on the login screen.
     */
    private void setUpGridPane() {
        gridPane.setPadding(new Insets(10, 10, 10, 10));
        gridPane.setVgap(5);
        gridPane.setHgap(10);

        gridPane.add(new Label("Username: "), 0, 0);
        gridPane.add(usernameField, 1, 0);

        gridPane.add(new Label("Password: "), 0, 1);
        gridPane.add(passwordField, 1, 1);

        gridPane.add(new Label(""), 0, 2);

        gridPane.add(new Label("Encryption Key-Pair: "), 0, 3);
        gridPane.add(encryptionPairButton, 1, 3);
        gridPane.add(encryptionFileCheckBox, 2, 3);

        gridPane.add(new Label("Encryption Key-Store Alias: "), 0, 4);
        gridPane.add(encryptionAlias, 1, 4);

        gridPane.add(new Label("Encryption Key-Store Password: "), 0, 5);
        gridPane.add(encryptionStorePassword, 1, 5);

        gridPane.add(new Label("Encryption Key Password: "), 0, 6);
        gridPane.add(encryptionPassword, 1, 6);

        gridPane.add(new Label(""), 0, 7);

        gridPane.add(new Label("Signing Key-Pair: "), 0, 8);
        gridPane.add(signingPairButton, 1, 8);
        gridPane.add(signatureFileCheckBox, 2, 8);

        gridPane.add(new Label("Signature Key-Store Alias: "), 0, 9);
        gridPane.add(signatureAlias, 1, 9);

        gridPane.add(new Label("Signature Key-Store Password: "), 0, 10);
        gridPane.add(signatureStorePassword, 1, 10);

        gridPane.add(new Label("Signature Key Password: "), 0, 11);
        gridPane.add(signaturePassword, 1, 11);
    }
}