package ObjectClasses;

import java.io.*;


/**
 * Object used to send both login and account creation requests to the server so that all parameters
 * are saved within one single object for easier access and unity with the requests, and they can be encrypted
 * together.
 *
 * @author Arvin Moshfegh
 * @version 1.0
 */
public class Request implements Serializable {
    private String username;
    private char[] password;

    /**
     * Constructor that creates a new request.
     *
     * @param username clients username
     * @param password clients password
     */
    public Request(String username, char[] password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Used to get this instances' username.
     *
     * @return Clients username as a string.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Used to get this instances' password.
     *
     * @return Clients password as char array.
     */
    public char[] getPassword() {
        return password;
    }


}
