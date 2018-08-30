package Sockets;

//Exception class for the Sockets package
public class SocketError extends Exception {

    public SocketError(String message, Throwable cause) {
        super(message, cause);
    }

    public SocketError(String message) {
        super(message);
    }

}
