package Msg;

public class Header {

    /*
      Packet/Header message format for this program:

      Message Format Header [version][message_type][encryption_mode][payload_length]
      Message Format Packet [total_fields][[field_length]....][[fields].....], where fields constitute arbitrary data given by the user
     
      version -- protocol version (Extended or Original)
      message_type -- specifies the message method
      encryption_mode -- specifies the encryption mode (ECB or CBC)
      payload_length -- length of the payload for this packet
    
     */
    public static final int HEADER_SIZE = 6;

    private byte protocol_version;
    private byte message_type;
    private byte protocol_mode;
    private int message_length = 0;

    private byte[] header; //internal storage

    //parses a header from a byte array
    public Header(byte[] header) throws MessageError {
        if (header.length == HEADER_SIZE) {
            this.header = header;
            protocol_version = header[0];
            message_type = header[1];
            protocol_mode = header[2];
            message_length = message_length + header[3];
            message_length = message_length + header[4];
            message_length = message_length + header[5];
        } else {
            throw new MessageError("Invalid Header Size");
        }
    }

    //generates a header given the following parameters
    //version, type , mode, plen
    public Header(int version, int type, int mode, int len) {
        header = new byte[HEADER_SIZE];
        protocol_version = (byte) version;
        message_type = (byte) type;
        protocol_mode = (byte) mode;
        message_length = len;
        header[0] = protocol_version;
        header[1] = this.message_type;
        header[2] = protocol_mode;
        int k = 3;
        int temp = len;
        while ((temp) > 127) {
            temp = temp - 127;
            header[k] = (byte) 127;
            k++;
        }
        header[k] = (byte) temp;
        k++;
        while (k < HEADER_SIZE) {
            header[k] = 0;
            k++;
        }

    }

    //public accessor methods .. 
    public byte[] getHeader() {
        return header;
    }

    public int getDataLength() {
        return message_length;
    }

    public byte getMessageType() {
        return message_type;
    }

    public int getProtocolMode() {
        return protocol_mode;
    }

    public int getProtoVersion() {
        return protocol_version;
    }

}
