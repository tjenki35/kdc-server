package Msg;

//Exception class for the msg package
public class MessageError extends Exception {

    public MessageError(String reason) {
        super(reason);
    }

    public MessageError(String reason, Exception ex) {
        super(reason, ex);
    }

}
