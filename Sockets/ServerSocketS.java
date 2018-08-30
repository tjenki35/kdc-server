package Sockets;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.net.ServerSocket;

public class ServerSocketS implements AutoCloseable {

    private ServerSocket self;

    //generates a ServerSocket wrapper and binds it the given port address
    public ServerSocketS(int port) throws SocketError { // create a server socket using the specified binding port
        try {
            self = new ServerSocket();
            InetSocketAddress address;
            address = new InetSocketAddress(InetAddress.getByName("localhost"), port);
            self.bind(address);
        } catch (UnknownHostException ex) {
            throw new SocketError("Cannot Connect to localhost", ex);
        } catch (IOException ex) {
            throw new SocketError("Cannot Connect to Networking Interface", ex);
        }
    }

    //creates a listening thread and returns a ClientSocketS on a successful connection
    public ClientSocketS listen() throws SocketError { // wait for incoming connection from a client ( blocks )
        try {
            return new ClientSocketS(self.accept());
        } catch (IOException ex) {
            throw new SocketError("Issue Connecting to Client", ex);
        }
    }

    //closes this object and all socket connections as gracefully as possible...hopefully
    @Override
    public void close() throws SocketError {
        try {
            self.close();
        } catch (IOException ex) {
            throw new SocketError("Error Closing Socket", ex);
        }

    }
}
