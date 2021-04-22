package Server;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.control.TextArea;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

/**
 * Server program used for communication between connected clients with encrypted/signed messages.
 *
 * @author Arvin Moshfegh
 * @version 1.0
 */
public class ServerGUI extends Application {
    private TextArea messageArea;
    private Stage primaryStage;
    private static String[] arguments;

    /**
     * Saves arguments provided and launches the program.
     *
     * @param args Server arguments needed to setup the private and public key of the server.
     *             Should provide info where the KeyStore is located, its alias, keypass and keystore pass.
     */
    public static void main(String[] args) {
        arguments = args;
        launch(args);
    }

    /**
     * Starts the JavaFX GUI by creating necessary nodes and creating a new Server.
     *
     * @param primaryStage JavaFX stage.
     */
    @Override
    public void start(Stage primaryStage) {
        this.primaryStage = primaryStage;
        BorderPane root = new BorderPane();
        createMessageArea();
        root.setCenter(messageArea);
        primaryStage.setScene(new Scene(root, 800, 600));
        primaryStage.addEventHandler(WindowEvent.WINDOW_CLOSE_REQUEST, new ExitHandler());
        primaryStage.show();
        new Server(this, arguments);
    }

    /**
     * Updates the title by calling on the JavaFX thread to run it when possible.
     *
     * @param newTitle New title that is being assigned to the GUI.
     */
    public void updateTitle(String newTitle) {
        Task<String> task = new Task<>() {
            @Override
            protected String call() throws Exception {
                primaryStage.setTitle(newTitle);
                return null;
            }
        };
        Platform.runLater(task);
    }


    /**
     * Displays a message on the server GUI.
     *
     * @param message Message to be shown in UI
     */
    public void updateMessageArea(String message) {
        messageArea.appendText(message + "\n");
    }

    /**
     * Creates the message area that shows messages being written.
     */
    private void createMessageArea() {
        messageArea = new TextArea();
        messageArea.setEditable(false);
        messageArea.textProperty().addListener(((observableValue, oldValue, newValue) ->
                messageArea.setScrollTop(Double.MAX_VALUE)));
    }

    /**
     * Inner class that handles closing the program by closing the window.
     */
    private class ExitHandler implements EventHandler<WindowEvent> {
        @Override
        public void handle(WindowEvent event) {
            event.consume();
            Platform.exit();
            System.exit(0);
        }
    }
}
