package Nodes;

public class ProtocolError extends Exception {

    public ProtocolError(String message) {
        super(message);
    }

    public ProtocolError(String message, Throwable cause) {
        super(message, cause);
    }

}
