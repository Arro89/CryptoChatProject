package ChatClient;

import ObjectClasses.Message;
import javafx.event.EventHandler;
import javafx.scene.control.TextArea;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCodeCombination;
import javafx.scene.input.KeyCombination;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.BorderPane;

/**
 * Graphical component for the ChatClient. Displays the BorderPane used for the chat.
 *
 * @author Arvin Moshfegh
 * @version 1.0
 */
public class ChatPane extends BorderPane {
    private ChatClient chatClient;
    private TextArea incomingMessageArea;
    private TextArea outgoingMessageArea;

    /**
     * Constructor for the ChatPane. Connects the GUI class to the chatClient and creates the message areas.
     *
     * @param chatClient Chat client that the chat pane is connected to.
     */
    public ChatPane(ChatClient chatClient) {
        this.chatClient = chatClient;
        createMessageArea();
        this.setCenter(incomingMessageArea);
        this.setBottom(outgoingMessageArea);
    }


    /**
     * Method to display messages on the upper textarea (used for incoming messages).
     *
     * @param time    Timestamp of message received
     * @param message MessageObject containing message to be displayed
     */
    public void showMessage(String time, Message message) {
        incomingMessageArea.appendText(String.format("%s - %s", time, message.toString()));
    }

    /**
     * Creates the components for the message area. Two TextAreas that are only scrollable vertically.
     */
    private void createMessageArea() {
        incomingMessageArea = new TextArea();
        incomingMessageArea.setEditable(false);
        incomingMessageArea.textProperty().addListener(((observableValue, oldValue, newValue) ->
                incomingMessageArea.setScrollTop(Double.MAX_VALUE)));
        incomingMessageArea.setWrapText(true);

        outgoingMessageArea = new TextArea();
        outgoingMessageArea.setOnKeyPressed(new OutgoingMessageHandler());
        outgoingMessageArea.textProperty().addListener(((observableValue, oldValue, newValue) ->
                incomingMessageArea.setScrollTop(Double.MAX_VALUE)));
        outgoingMessageArea.setWrapText(true);
        outgoingMessageArea.setPrefHeight(100);
    }


    /**
     * Inner handler class that deals with key inputs. If the user presses Enter in the outgoingMessageArea the message
     * will be sent. Also handles SHIFT+ENTER key combination to make a new line in the message.
     */
    private class OutgoingMessageHandler implements EventHandler<KeyEvent> {
        private final KeyCombination keyCombination = new KeyCodeCombination(KeyCode.ENTER, KeyCombination.SHIFT_DOWN);

        @Override
        public void handle(KeyEvent keyEvent) {
            if (keyCombination.match(keyEvent)) {
                outgoingMessageArea.appendText("\n");
            } else {
                KeyCode keyCode = keyEvent.getCode();
                if (keyCode.equals(KeyCode.ENTER)) {
                    chatClient.sendMessage(outgoingMessageArea.getText());
                    outgoingMessageArea.clear();
                }
            }
        }
    }
}
