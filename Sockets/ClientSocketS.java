package Sockets;

import Msg.Header;
import Msg.MessageError;
import Msg.Packet;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class ClientSocketS implements AutoCloseable {

    private Socket self;
    private DataOutputStream out;
    private DataInputStream in;

    public static int HEADER_SIZE = Header.HEADER_SIZE; 

    //generates a ClientSocket and connects it to the given IP address and port, originating from this localhost
    public ClientSocketS(String ip, int port) throws SocketError {
        //generate a new underlying socket
        self = new Socket();
        InetSocketAddress address;
        try {
            address = new InetSocketAddress(InetAddress.getByName(ip), port);
            self.connect(address); // attempt to connect to given address
        } catch (UnknownHostException ex) {
            throw new SocketError("Cannot Connect to Host", ex);
        } catch (IOException ex) {
            throw new SocketError("Cannot Connect to Networking Interface", ex);
        }
    }

    // bind a java socket as the underlying API for the protocol socket
    public ClientSocketS(Socket socket) {
        self = socket; 
    }
    //public API to send a Packet from this socket
    public void send_pkt(Packet packet) throws SocketError, MessageError {
        if(packet.data==null){
            if(packet.fields!=null){
                 packet.pack();
            }else{
                //throw new ProtocolError 
            }
        }
        byte[] data = packet.data;
        Header header = new Header(packet.protocol_version, packet.message_type, packet.protocol_mode, data.length);
        send_bytes(header.getHeader());
        send_bytes(data);
    }

    //public API to recieve a Packet from this socket
    public Packet recv_pkt() throws SocketError, MessageError {
        Header header = new Header(recv_header());
        byte[] payload = recv_payload(header.getDataLength());
        Packet pkt = new Packet(payload);
        pkt.message_type = header.getMessageType();
        pkt.protocol_mode = header.getProtocolMode();
        pkt.protocol_version = header.getProtoVersion();
        
        return pkt;
    }
    
    //parses a header from the wire, (rudementary timeout code has been included)
    private byte[] recv_header() throws SocketError {
        byte[] buffer = new byte[HEADER_SIZE];
        int total_bytes = 0;
        int failsafe = 1024;
        try {
            while (total_bytes < HEADER_SIZE) {
                byte read = in.readByte();
                buffer[total_bytes] = read;
                total_bytes++;
                //read logic here
                failsafe--;
                if (failsafe < 0) {
                    throw new SocketError("No apparent data to read, (or too large of a response)");
                }
            }
        } catch (IOException ex) {
            throw new SocketError("Error Reading Header", ex);
        }
        return buffer;
    }

    //retrieves an arbitrary number of bytes from the wire, (rudementary timeout code has been included)
    private byte[] recv_payload(int len) throws SocketError {
        byte[] buffer = new byte[len];
        int total_bytes = 0;
        int failsafe = 1024;
        try {
            while (total_bytes < len) {
                byte read = in.readByte();
                buffer[total_bytes] = read;
                total_bytes++;
                //read logic here
                failsafe--;
                if (failsafe < 0) {
                    throw new SocketError("No apparent data to read, (or too large of a response)");
                }
            }
        } catch (IOException ex) {
            throw new SocketError("Error Reading Bytes", ex);
        }
        return buffer;
    }
    
    //private API to send arbitary bytes over this socket
    private void send_bytes(byte[] input) throws SocketError {
        try {
            out.write(input);
            out.flush();
        } catch (IOException ex) {
            throw new SocketError("Error Sending Bytes", ex);
        }
    }

    //attempts to open up input and output streams for this socket connection
    public void open() throws SocketError { 
        try {
            out = new DataOutputStream(new BufferedOutputStream(self.getOutputStream()));
            in = new DataInputStream(self.getInputStream());

        } catch (IOException ex) {
            throw new SocketError("Error Opening Socket Streams", ex);
        }
    }

    //returns this particular socets InetAddress
    public InetAddress getAddress() {
        return self.getInetAddress();
    }

    @Override
    public void close() throws SocketError { // shutdown the socket, note the this class is not safe to use after this function is activated.
        try {
            out.close();
            in.close();
            self.close();
        } catch (IOException ex) {
            throw new SocketError("Error Closing Socket", ex);
        }

    }
}
