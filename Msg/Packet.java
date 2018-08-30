package Msg;

import Cipher.Cipher3DES;
import static Cipher.Cipher3DES.BLOCK_SIZE;
import static Cipher.Cipher3DES.ECB;
import Cipher.Nonces;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

/*
Packet/Header message format for this program:

Message Format Header [version][message_type][encryption_mode][payload_length]
Message Format Packet [total_fields][[field_length]....][[fields].....], where fields constitute arbitrary data given by the user
 */
//The packet class is the primary mode of data aggregation for this program. 
//The sockets implementation supports the recieving and sending of the Packet class format
//Mainly this class is so we don't have to deal with byte operations manually
public class Packet {

    //Static indentifiers for message types
    public final static int ESTABLISH = 0;
    public final static int REQUEST = 1;
    public final static int CONTACT = 2;
    public final static int RESPONSE = 3;
    public final static int ORIGINAL_SCH = 1;
    public final static int EXTENDED_SCH = 2;
    public final static String INVALID = "INVALID";

    //number of fields attached to this packet
    private final ArrayList<Byte> field_lengths = new ArrayList<>(); //(contains lengths, used for data generation)
    //the actual field objects, exposed to the user
    public ArrayList<Field> fields = new ArrayList<>(); //(**note: may not be filled until generate_fields is called)
    public byte[] data; //parse data (**note: may not be filled until generate_data is called)

    public int message_type = ESTABLISH; // default message type (Establish)
    public int protocol_mode = ECB;
    public int protocol_version = ORIGINAL_SCH;

    //create a packet with the given input as the data field
    public Packet(byte[] input) {
        data = input;
    }

    //create an empty packet
    public Packet() {

    }

    //creates a packet w/ the given configuration
    public Packet(int ver, int mode, int type) {
        message_type = type;
        protocol_mode = mode;
        protocol_version = ver;
    }

    //add a new field to this packet
    public void addField(byte[] bytes) {
        fields.add(new Field(bytes));
        addLength(bytes.length);
    }

    //The two encoding/decoding classes are the main focus in the Packet class. 
    //generate field objects based on the information stored in the data field
    public void generateFields() throws MessageError {
        Packet.decodeMode(protocol_mode);
        Packet.decodeVersion(protocol_version);
        Packet.decodeType(message_type);

        int fi = data[0] + 1;
        if (fi >= BLOCK_SIZE) {
            throw new MessageError("Too many fields, 7 maximum");
        }
        int k = 1;
        for (int i = 0; i < fi; i++) {
            if (k < fi) {
                field_lengths.add(data[k]);
            }
            k++;
        }
        k = BLOCK_SIZE;
        for (byte l : field_lengths) {
            byte[] temp = new byte[l];
            for (int i = 0; i < l; i++) {
                if (k >= data.length) {
                    break;
                }
                temp[i] = data[k];
                k++;
            }
            fields.add(new Field(temp));
        }
    }

    //prepares the data to be transmitted, new fields will have no effect until next call.
    public void pack() throws MessageError {
        Packet.decodeMode(protocol_mode);
        Packet.decodeVersion(protocol_version);
        Packet.decodeType(message_type);

        int total_size = 0;// = field_lengths.size();
        for (byte b : field_lengths) {
            total_size += b;
        }
        data = new byte[total_size + BLOCK_SIZE];
        int k = 1;
        data[0] = (byte) field_lengths.size();
        for (byte b : field_lengths) {
            data[k] = b;
            k++;
        }

        byte[] rand = Nonces.generateNonce(); // rather than fill with all zeros
        while (k < 8) {
            data[k] = rand[k];
            k++;
        }

        for (Field f : fields) {
            for (byte b : f.bytes) {
                data[k] = b;
                k++;
            }
        }
    }

    //print packet to the standard output
    public void print_packet(String heading) throws MessageError {
        System.out.println("\nPacket");
        System.out.println(heading);
        System.out.println("Type: " + decodeType(message_type));
        System.out.println("Version: " + decodeVersion(protocol_version));
        System.out.println("Encryption Mode: " + decodeMode(protocol_mode));
        System.out.println("Size: " + data.length);
        System.out.println("Payload:");
        System.out.println("Packet Payload: ");
        System.out.println("-----------------------------------------------------");
        System.out.println(Arrays.toString(data));
        System.out.println("-----------------------------------------------------");
        System.out.println("\n");
    }

    public static String decodeType(int type) throws MessageError {
        switch (type) {
            case Packet.CONTACT:
                return "CONTACT";
            case Packet.ESTABLISH:
                return "ESTABLISH";
            case Packet.REQUEST:
                return "REQUEST";
            case Packet.RESPONSE:
                return "RESPONSE";
            default:
                throw new MessageError("Invalid Message Type");
        }
    }

    public static String decodeVersion(int mode) throws MessageError {
        switch (mode) {
            case Packet.EXTENDED_SCH:
                return "EXTENDED_SCH";
            case Packet.ORIGINAL_SCH:
                return "ORIGINAL_SCH";
            default:
                throw new MessageError("Invalid Version Specified");
        }
    }

    public static String decodeMode(int mode) throws MessageError {
        switch (mode) {
            case Cipher3DES.CBC:
                return "CBC";
            case Cipher3DES.ECB:
                return "ECB";
            default:
                throw new MessageError("Invalid Mode Specified");

        }
    }

    //I/O API to write packets to file
    public static void write_packets(String filename, ArrayList<byte[]> packets) {
        try {
            DataOutputStream stream = new DataOutputStream(new FileOutputStream(filename));
            stream.writeInt(packets.size());
            for (byte[] pkt : packets) {
                stream.writeInt(pkt.length);
                for (byte b : pkt) {
                    stream.writeByte(b);
                }

            }
        } catch (FileNotFoundException ex) { //not critical functions
            System.out.println("Cannot save packet to file, file not found");
        } catch (IOException ex) {
            System.out.println("Cannot save packet to file, IO exception ");
        }
    }

    //I/O API to read packets from file
    public static ArrayList<Packet> read_packets(String filename) {
        ArrayList<Packet> packets = new ArrayList<>();
        try {
            DataInputStream stream = new DataInputStream(new FileInputStream(filename));
            int num_packets = stream.readInt();
            for (int i = 0; i < num_packets; i++) {
                Packet pkt = new Packet();
                int size = stream.readInt();
                pkt.data = new byte[size];
                for (int j = 0; j < size; j++) {
                    pkt.data[j] = stream.readByte();
                }
                packets.add(pkt);
            }
        } catch (FileNotFoundException ex) { //not critical functions
            System.out.println("Cannot read packet from file, file not found");
        } catch (IOException ex) {
            System.out.println("Cannot read packet from file, IO exception ");
        }
        return packets;
    }

    //add a length to the packet (internal use only)
    private void addLength(int len) {
        field_lengths.add((byte) len);
    }
}
