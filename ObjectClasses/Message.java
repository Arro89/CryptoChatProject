package ObjectClasses;

import java.io.Serializable;

/**
 * Serializable custom Message object used to encapsulate both sender and message being transferred to another client.
 *
 * @author Arvin Moshfegh
 * @version 1.0
 */
public class Message implements Serializable {
    private String sender;
    private String message;

    /**
     * Constructor for the Message object that sets the sender and message.
     *
     * @param sender  String of the senders username
     * @param message String of the message being sent
     */
    public Message(String sender, String message) {
        this.sender = sender;
        this.message = message;
    }

    /**
     * To string method that returns a string format of the Message content for easier display and handling.
     *
     * @return Returns the message, formatted as sender: message.
     */
    @Override
    public String toString() {
        return String.format("%s: %s", sender, message);
    }

}
