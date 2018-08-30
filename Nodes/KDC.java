package Nodes;

import Simulation.PubKeys;
import Cipher.Cipher3DES;
import static Cipher.Cipher3DES.DECRYPT_MODE;
import static Cipher.Cipher3DES.ENCRYPT_MODE;
import Cipher.CipherDiffie;
import Cipher.CipherError;
import Cipher.CipherRSA;
import Cipher.Truple;
import Msg.MessageError;
import Msg.Packet;
import static Msg.Packet.ESTABLISH;
import static Msg.Packet.EXTENDED_SCH;
import static Msg.Packet.REQUEST;
import Simulation.PubKeys.pub_info;
import Sockets.ClientSocketS;
import Sockets.ServerSocketS;
import Sockets.SocketError;
import java.math.BigInteger;
import javax.crypto.SecretKey;

public class KDC {

    private BigInteger private_key;

    //bind private key ( generated using CipherRSA )
    private static String name;

    //get some public key information
    private final PubKeys pub_keys = new PubKeys();
    private final KeyStore store = new KeyStore();
    // private final HashMap<String, Truple<SecretKey>> shared_keys = new HashMap<>();
    private final BigInteger public_modulus;
    private int running_port = 0;
    //private int mode = ECB;

    public KDC(String identity, int port) throws ResourceError {
        name = identity;
        pub_info KDC = pub_keys.get_info(name);
        public_modulus = KDC.public_modulus;
        running_port = port;
    }

    public void addPrivateKey(String pk) {
        private_key = new BigInteger(pk);
    }

    public void run() {
        if (private_key == null) {
            return;
        }
        try {
            //todo patch in multi-threading

            ServerSocketS server = new ServerSocketS(running_port);
            while (true) {
                ClientSocketS client = server.listen();
                try {
                    client.open();
                    Packet packet = client.recv_pkt();
                    switch (packet.message_type) {
                        case ESTABLISH:  //registration w/ KDC (Name) -- cleartext
                            registerUser(client, packet);
                            break;
                        case REQUEST:  //request for ticket
                            parseRequest(client, packet);
                            break;
                        default:
                            //throw new ProtocolError()
                            System.out.println("Invalid Message Type from Client");
                            break;
                    }
                } catch (SocketError | MessageError | CipherError | ResourceError | ProtocolError ex) {
                    System.err.println(ex.getMessage());
                }
            }

        } catch (SocketError ex) {
            System.out.println("Cannot Start Server w/ specified parameters");
            System.err.println(ex.getMessage());
        }
    }

    //setup a shared key between the client and this KDC
    private void registerUser(ClientSocketS socket, Packet packet) throws CipherError, SocketError, MessageError, ResourceError, ProtocolError {

        int mode = packet.protocol_mode;
        int version = packet.protocol_version;

        packet.generateFields();
        String username = new String(packet.fields.get(0).bytes);

        System.out.println("Contact from " + username + " to establish shared key");

        //get public key information on client
        pub_info client = pub_keys.get_info(username);
        if (client == null) {
            throw new ResourceError("Client not Found!: " + username);
        }
        BigInteger cpub_e = client.public_exponent;
        BigInteger cpub_n = client.public_modulus;

        //send TB to the other side (encrypted w/ the pub rsa key)
        BigInteger secret = CipherDiffie.generateSecret();
        BigInteger T_B = CipherDiffie.prepareMessage(PubKeys.PUBLIC_G, PubKeys.PUBLIC_P, secret);
        BigInteger c = CipherRSA.encrypt(T_B, cpub_e, cpub_n);
        byte[] cbytes = c.toByteArray();

        Packet send = new Packet(version, mode, Packet.ESTABLISH);
        send.data = cbytes;
        send.message_type = 0;
        socket.send_pkt(send);

        //get last payload from client containing the encrypted TA 
        Packet recv = socket.recv_pkt();

        BigInteger T_A = CipherRSA.decrypt(new BigInteger(1, recv.data), private_key, public_modulus);
        BigInteger s_AB = CipherDiffie.combineSecrets(T_A, PubKeys.PUBLIC_P, secret);

        //generate a shared key from the Diffie Hellman process to encrypted a "high quality" seeded keyset (one time use only)
        Truple<SecretKey> shared_key = Cipher3DES.generateFromShared(s_AB);

        //generate a seeded keyset to transmit
        Truple<SecretKey> seeded_keys = Cipher3DES.generatedFromSeed();

        System.out.println("Generated Shared Keys for " + username + ":\n" + seeded_keys.toString());

        //generate a new packet to send containing the seeded shared keys for the two nodes
        send = new Packet();
        send.message_type = Packet.ESTABLISH;
        send.addField(seeded_keys.first.getEncoded());
        send.addField(seeded_keys.second.getEncoded());
        send.addField(seeded_keys.third.getEncoded());
        send.pack();

        //encrypt the packet using the Diffie Hellman derived key and send the seeded keys on their way
        Cipher3DES cipher = new Cipher3DES(shared_key, ENCRYPT_MODE, mode);
        send.data = cipher.encrypt(send.data);
        socket.send_pkt(send);

        store.put(username, seeded_keys);
        //shared_keys.put(username, seeded_keys); // should just wipe out old records
    }

    //receive request from user for contact with another
    public void parseRequest(ClientSocketS socket, Packet packet) throws CipherError, SocketError, ResourceError, ProtocolError, MessageError {

        //generate and validate
        packet.generateFields();

        int mode = packet.protocol_mode;
        int version = packet.protocol_version;

        int argc = 3;
        if (version == EXTENDED_SCH) {
            argc = 4;
        }

        if (packet.fields.size() != argc) {
            System.out.println("Invalid Request, Aborting");
            //throw new ProtocolError()
            return;
        }

        //there should be three fields ( nonce, client, requested name )
        String[] fields = new String[]{
            new String(packet.fields.get(0).bytes),
            new String(packet.fields.get(1).bytes),
            new String(packet.fields.get(2).bytes)
        };

        // some mild validation stuff
        String field1 = new String(packet.fields.get(1).bytes);
        packet.print_packet("Received Packet (Message 1); (nonce_1, a.identity, b.identity, **enc_B(nonce_B)) from: " + field1);

        //if (!shared_keys.containsKey(field1)) {
        //    throw new ResourceError("Server does not know resource : " + field1);
        //}
        //String field2 = new String(packet.fields.get(2).bytes);
        //if (!shared_keys.containsKey(field2)) {
        //    throw new ResourceError("Server does not know resource : " + field2);
        //}
        Truple<SecretKey> client_b_keys = store.get_keys(fields[2]);
        //Truple<SecretKey> client_b_keys = shared_keys.get(fields[2]);
        byte[] ex_field = null;
        if (version == EXTENDED_SCH) {
            ex_field = packet.fields.get(3).bytes;
            Cipher3DES cipher = new Cipher3DES(client_b_keys, DECRYPT_MODE, mode);
            ex_field = cipher.decrypt(ex_field);
        }
        //invent a key K_AB
        Truple<SecretKey> mediated_keys = Cipher3DES.generateKeys();
        //Truple<SecretKey> client_a_keys = shared_keys.get(fields[1]);
        Truple<SecretKey> client_a_keys = store.get_keys(fields[1]);

        byte[] f0 = packet.fields.get(0).bytes;
        byte[] f1 = fields[1].getBytes();
        byte[] f2 = fields[2].getBytes();
        byte[] kenc1 = mediated_keys.first.getEncoded();
        byte[] kenc2 = mediated_keys.second.getEncoded();
        byte[] kenc3 = mediated_keys.third.getEncoded();

        //build the ticket first
        Packet ticket = new Packet();
        ticket.addField(f1);
        ticket.addField(kenc1);
        ticket.addField(kenc2);
        ticket.addField(kenc3);
        if (version == EXTENDED_SCH) {
            ticket.addField(ex_field);
        }
        ticket.pack();

        Cipher3DES cipher = new Cipher3DES(client_b_keys, ENCRYPT_MODE, mode);

        ticket.data = cipher.encrypt(ticket.data);

        Packet message = new Packet(version, mode, Packet.RESPONSE);
        message.addField(f0);
        message.addField(f2);
        message.addField(kenc1);
        message.addField(kenc2);
        message.addField(kenc3);
        message.addField(ticket.data);
        message.pack();

        cipher.setKeys(client_a_keys);
        cipher.reinit(ENCRYPT_MODE, mode);
        message.data = cipher.encrypt(message.data);

        message.print_packet("Sending Packet (Message 2); enc_A(nonce_1, b.identity, keys, ticket) to: " + field1);

        socket.send_pkt(message);

    }
}
