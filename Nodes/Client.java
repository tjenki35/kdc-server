package Nodes;

import Simulation.PubKeys;
import Cipher.Cipher3DES;
import static Cipher.Cipher3DES.DECRYPT_MODE;
import static Cipher.Cipher3DES.ECB;
import static Cipher.Cipher3DES.ENCRYPT_MODE;
import Cipher.CipherDiffie;
import Cipher.CipherError;
import Cipher.CipherRSA;
import Cipher.NonceError;
import Cipher.Nonces;
import Cipher.Truple;
import Msg.Field;
import Msg.MessageError;
import Msg.Packet;
import static Msg.Packet.CONTACT;
import static Msg.Packet.EXTENDED_SCH;
import static Msg.Packet.ORIGINAL_SCH;
import static Msg.Packet.REQUEST;
import static Simulation.PubKeys.KDC;
import Simulation.PubKeys.pub_info;
import Sockets.ClientSocketS;
import Sockets.ServerSocketS;
import Sockets.SocketError;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

//This serves as the base client class (extended by the client interfaces A and B)
//there are two parts to the client class (client mode and server mode)
//any client can authenticate to the KDC (provided they are recognized and have public keys known to the KDC)
//also any client can put them selves into server mode to await incoming authentications from another client
public class Client { //in this scenario both nodes are clients of the KDC

    public String identity;
    protected BigInteger private_key;
    protected BigInteger public_exponent;
    protected BigInteger public_modulus;

    //public key information
    private final PubKeys public_keys = new PubKeys();
    //maps shared keys to resource ids
    private final KeyStore store = new KeyStore();
    //maps nonces to verify accross multi-connection authentication
    private final AuthMap map = new AuthMap();

    //mode and version for the client portion of the class, the Server portion does not use these class values 
    private int mode = ECB;
    private int version = ORIGINAL_SCH; // refers to normal version of the schroeder exchange, 1 refers to the extended version

    //(gives a switch for this to turn off all functions (server and client related, since they can be running in different threads)
    AtomicBoolean active = new AtomicBoolean(true);

    //Public constructor, generares all of the resources for this node
    public Client(String id) throws ResourceError {
        identity = id;
        pub_info self = public_keys.get_info(identity);
        public_exponent = self.public_exponent;
        public_modulus = self.public_modulus;
    }

    //this method requests a authentication ticket from the KDC
    public byte[] requestTicket(String query, String host, int port, String server_id) throws SocketError, ProtocolError, NonceError, ResourceError, CipherError, MessageError {

        //verify we have public key information for the server id
        pub_info server = public_keys.get_info(server_id);
        if (server == null) {
            throw new ResourceError(server_id + "not found in public records!");
        }

        Cipher3DES cipher;

        //connect to the KDC
        ClientSocketS socket = new ClientSocketS(host, port);
        socket.open();

        //build and send the first packet
        byte[] nonce = Nonces.generateNonce();
        Packet send = new Packet(version, mode, Packet.REQUEST);
        send.addField(nonce);
        send.addField(identity.getBytes());
        send.addField(query.getBytes());

        if (version == EXTENDED_SCH) { //if we are in the extended mode we add an additional field
            byte[] mapped = map.get_mapped(query);
            send.addField(mapped);
        }

        send.pack();
        send.print_packet("Sending Packet (Message 1); (nonce_1, a.identity, b.identity, **enc_B(nonce_B)) to: " + server_id);
        socket.send_pkt(send);

        //recieve the response from the server
        Packet recv = socket.recv_pkt();

        recv.print_packet("Received Packet (Message 2); enc_A(nonce_1, b.identity, keys, ticket) from: " + server_id);

        //get the previously established shared key with the KDC
        Truple<SecretKey> resource_key = store.get_keys(server.name);

        cipher = new Cipher3DES(resource_key, DECRYPT_MODE, mode);

        recv.data = cipher.decrypt(recv.data);
        recv.generateFields();

        ArrayList<Field> fields = recv.fields;

        //some validation
        if (fields.size() != 6) {
            throw new ProtocolError("Invalid Message from Resource: " + server_id);
        }

        //verification for the name query (to prevent impersonation of the KDC)
        String id_B = new String(fields.get(1).bytes);
        if (!id_B.equals(query)) {
            throw new ProtocolError("Invalid Query to Server");
        }

        //verification for the nonce (to verify that the KDC knows our shared key)
        int i = 0;
        for (byte b : nonce) {
            if (b != fields.get(0).bytes[i]) {
                throw new NonceError("Invalid Nonce, security failure");
            }
            i++;
        }

        //retrieve encoded keys (encoded into the packet)
        SecretKeySpec key1 = new SecretKeySpec(fields.get(2).bytes, 0, fields.get(2).bytes.length, "DES");
        SecretKeySpec key2 = new SecretKeySpec(fields.get(3).bytes, 0, fields.get(3).bytes.length, "DES");
        SecretKeySpec key3 = new SecretKeySpec(fields.get(4).bytes, 0, fields.get(4).bytes.length, "DES");

        //generate a keyset from the encoded information
        Truple<SecretKey> keys = new Truple(key1, key2, key3);

        //save the shared keys between A and B
        store.put(id_B, keys);

        //return the ticket as the next message to send to Bob.
        return fields.get(5).bytes;

    }

    //requests a nonce from the client we want to talk to (pre1-pre2 for Extended protocol)
    public void requestNonce(String host, int port) throws SocketError, MessageError, ProtocolError {
        if (version == EXTENDED_SCH) {

            ClientSocketS socket = new ClientSocketS(host, port);
            socket.open();
            Packet pkt = new Packet(version, mode, Packet.REQUEST);
            pkt.addField("HELO".getBytes());
            pkt.addField(this.identity.getBytes());
            pkt.pack();

            socket.send_pkt(pkt);

            pkt.print_packet("Sending Packet (Message pre-1); HELO, Identity: ");

            Packet recv = socket.recv_pkt();

            recv.generateFields();
            String f1 = new String(recv.fields.get(1).bytes);

            recv.print_packet("Received Packet (Message pre-2); enc_B(nonce_B) from: " + f1);

            if (recv.fields.size() == 2) {
                map.put(f1, recv.fields.get(0).bytes);
            } else {
                throw new ProtocolError("Invalid Message from Resource");
            }
        }
    }

    //establishes the inital K_Client with the KDC (does some public crypto to share the key) -- Still need to patch the small M vuln 
    public void authenticateKDC(String host, int port, String resource_id) throws ResourceError, SocketError, MessageError, CipherError {
        System.out.println("Generating Public Key Information.....");
        pub_info resource = public_keys.get_info(resource_id);
        if (resource == null) {
            throw new ResourceError(resource_id + "not found in public records!");
        }
        ClientSocketS socket = new ClientSocketS(host, port);
        socket.open();

        System.out.println("Establishing Identity w/ KDC using RSA and Diffie Hellman.....");

        //send identification to KDC
        Packet send = new Packet(version, mode, Packet.ESTABLISH);
        send.addField(identity.getBytes());

        send.pack();
        socket.send_pkt(send);

        //receive information encrypted w/ this client's public key
        Packet recv = socket.recv_pkt();

        //this should contain an encrypted version of the diffie hellman challenge ( should be padded too )
        BigInteger T_B = CipherRSA.decrypt(new BigInteger(recv.data), private_key, public_modulus);

        //generate secret
        BigInteger secret = Cipher.CipherDiffie.generateSecret();

        //generate response
        BigInteger T_A = CipherDiffie.prepareMessage(PubKeys.PUBLIC_G, PubKeys.PUBLIC_P, secret);
        T_A = CipherRSA.encrypt(T_A, resource.public_exponent, resource.public_modulus);

        //send back response
        send = new Packet(version, mode, Packet.ESTABLISH);
        //send.message_type = Packet.ESTABLISH;
        send.data = T_A.toByteArray();
        socket.send_pkt(send);
        //end of response

        //we should have the same shared secret on both sides now
        BigInteger s_AB = CipherDiffie.combineSecrets(T_B, PubKeys.PUBLIC_P, secret);

        Truple<SecretKey> shared_secret = Cipher3DES.generateFromShared(s_AB);
        Cipher3DES cipher = new Cipher3DES(shared_secret, DECRYPT_MODE, mode);

        recv = socket.recv_pkt();
        recv.data = cipher.decrypt(recv.data);
        recv.generateFields();
        store.put(resource_id, Truple.parseTruple(recv.fields.get(0).bytes, recv.fields.get(1).bytes, recv.fields.get(2).bytes));

        System.out.println("Established KeySet (KDC): ");
        System.out.println(store.get_keys(resource_id).toString());

        //now we are done with the shared key establishment
    }

    //authenticates this client given a particular ticket recieved from the KDC
    public void authenticate(String host, int port, String resource_id, byte[] ticket) throws CipherError, SocketError, NonceError, MessageError, ResourceError {

        //get the shared key, which is mapped to the resource_id
        Truple<SecretKey> resource_key = store.get_keys(resource_id);

        ClientSocketS socket = new ClientSocketS(host, port);
        socket.open();

        Packet auth_message = new Packet(version, mode, Packet.CONTACT);
        auth_message.addField(ticket);
        byte[] nonce2 = Nonces.generateNonce();

        //encrypt the nonce, but not the ticket. This exposes a little bit of the packet information but the data is still encrypted
        Cipher3DES cipher = new Cipher3DES(resource_key, ENCRYPT_MODE, mode);
        auth_message.addField(cipher.encrypt(nonce2));
        auth_message.pack();

        auth_message.print_packet("Sending Packet (Message 3); ticket, enc_AB(nonce_2) to: " + resource_id);
        socket.send_pkt(auth_message);

        //**Prep for reflection attack -- note : a real attacker would have to do this off of the "wire"
        ArrayList<byte[]> wireshark = new ArrayList<>();
        //(this part will always be "sniffed" to file)
        wireshark.add(auth_message.data);
        //end packet capture

        Packet recv = socket.recv_pkt();

        //as well as write this message to file for Trudy
        wireshark.add(recv.data);
        //Packet.write_packets("./resources/packets.pkts", wireshark);
        //end packet capture

        recv.print_packet("Received Packet (Message 4); enc_AB(nonce_2 - 1, nonce_3) from: " + resource_id);

        //decrypt and parse packet
        cipher.reinit(DECRYPT_MODE, mode);
        recv.data = cipher.decrypt(recv.data);
        recv.generateFields();

        ArrayList<Field> fields = recv.fields;
        byte[] nonce2_ = fields.get(0).bytes;

        //verify nonce, an error will be raised if this fails
        Nonces.verifyNonce(nonce2, nonce2_);

        //modify nonce and encrypt the packet
        byte[] nonce3_ = Nonces.changeNonce(fields.get(1).bytes);

        Packet send = new Packet(version, mode, Packet.CONTACT);
        send.addField(nonce3_);
        send.pack();

        cipher.reinit(ENCRYPT_MODE, mode);
        send.data = cipher.encrypt(send.data);

        send.print_packet("Sending Packet (Message 5); enc_AB(nonce_3 - 1) to: " + resource_id);

        //trudy can also capture this packet, which will prove to be useful for crafting a fake packet. This packet is encrytped, but using the header info when encrypted is key
        wireshark.add(send.data);
        Packet.write_packets("./resources/packets.pkts", wireshark);
        //end packet capture

        socket.send_pkt(send);

        // At this point the authentication is finished...we could use a newly generated session key to communication further. 
        System.out.println("Authentication for client " + this.identity + " to " + resource_id + " has completed without errors");
        System.out.println("Shared Key Established:");
        System.out.println(resource_key);
    }

    /*
        Server Portion of the Client class (client-listening mode if you will)
     */
    public void setupServer(int port) {
        try {
            //Generates a wrapped server socket for incoming connections
            ServerSocketS listen = new ServerSocketS(port);

            while (active.get()) {
                ClientSocketS client = listen.listen();

                //wraps each connection in a thread process (to allow for multiple connections)
                Thread process = new Thread(() -> {

                    try {
                        client.open(); // open up streams

                        Packet recv = client.recv_pkt();
                        //we override the current mode and versions for backwards compatibility
                        int ver = recv.protocol_version;
                        int type = recv.message_type;

                        //some verification
                        if (ver == ORIGINAL_SCH) {
                            if (type == CONTACT) {
                                authenticate_response(client, recv);
                            } else {
                                throw new ProtocolError("Invalid Version Type: " + ver);
                            }
                        } else if (ver == EXTENDED_SCH) {
                            switch (type) {
                                case REQUEST:
                                    initial_request(client, recv);
                                    break;
                                case CONTACT:
                                    authenticate_response(client, recv);
                                    break;
                                default:
                                    throw new ProtocolError("Invalid Message Type: " + type);
                            }
                        }
                    } catch (MessageError | SocketError | CipherError | NonceError | ProtocolError | ResourceError ex) {
                        System.err.println(ex.getMessage());
                    }
                });
                process.start(); // send client process off to another thread
            }
        } catch (SocketError ex) {
            System.err.println("Cannot Start Server");
            System.err.println(ex.getMessage());
        }
    }

    //processes authenticate from clientA (messages 3, 4, and 5) where the user provides a ticket and a nonce
    public void authenticate_response(ClientSocketS client, Packet recv) throws CipherError, NonceError, SocketError, MessageError, ProtocolError, ResourceError {

        //verify and parse packet
        recv.generateFields();

        int en_mode = recv.protocol_mode;
        int proto_version = recv.protocol_version;

        ArrayList<Field> fields = recv.fields;

        Truple<SecretKey> key_kdc = store.get_keys(KDC);

        //geneate the decrypted packet and validate ticket
        Cipher3DES cipher = new Cipher3DES(key_kdc, DECRYPT_MODE, en_mode);
        Packet ticket = new Packet(cipher.decrypt(fields.get(0).bytes));

        ticket.generateFields();
        ArrayList<Field> ticketFields = ticket.fields;

        //ticket argument validation
        int argc = 4;
        if (proto_version == EXTENDED_SCH) {
            argc = 5;
        }

        if (ticketFields.size() != argc) {
            throw new ProtocolError("Invalid Message from Resource");
        }

        //parse the shared key
        String resource_id = new String(ticketFields.get(0).bytes);

        recv.print_packet("Received Packet (Message 3); ticket, enc_AB(nonce_2) from: " + resource_id);

        //todo error handling here
        Truple<SecretKey> resource_key = Truple.parseTruple(ticketFields.get(1).bytes, ticketFields.get(2).bytes, ticketFields.get(3).bytes);
        store.put(resource_id, resource_key);

        //if it is the extended version we need to retrieve the saved value from initialResponse
        if (version == EXTENDED_SCH) {
            byte[] mapped = map.get_mapped(resource_id);
            byte[] compare = ticket.fields.get(4).bytes;
            int k = 0;
            for (byte b : mapped) {
                if (compare[k] != b) {
                    throw new NonceError("Nonce does not match, aborting");
                }
            }
        }

        //decrypt the nonce, while generating a new one to send
        byte[] nonce2 = fields.get(1).bytes;
        cipher.setKeys(resource_key);
        cipher.reinit(DECRYPT_MODE, en_mode);

        //change the nonce for validation, generate a new one and send the packet off after encrypting 
        nonce2 = cipher.decrypt(nonce2);
        byte[] nonce2_ = Nonces.changeNonce(nonce2);
        byte[] nonce3 = Nonces.generateNonce();

        Packet packet = new Packet(proto_version, en_mode, Packet.RESPONSE);
        packet.addField(nonce2_);
        packet.addField(nonce3);
        packet.pack();
        cipher.reinit(ENCRYPT_MODE, en_mode);

        packet.data = cipher.encrypt(packet.data);

        packet.print_packet("Sending Packet (Message 4); enc_AB(nonce_2 - 1, nonce_3) to: " + resource_id);

        client.send_pkt(packet);

        //recieve the last packet from the clientA
        recv = client.recv_pkt();

        recv.print_packet("Received Packet (Message 5); enc_AB(nonce_3 - 1) from: " + resource_id);

        //decrypt and verify change to the nonce
        cipher.reinit(DECRYPT_MODE, en_mode);
        recv.data = cipher.decrypt(recv.data);

        recv.generateFields();
        byte[] nonce3_ = recv.fields.get(0).bytes;

        //this will verify that the user sent a valid changed nonce, there authenticating the user
        Nonces.verifyNonce(nonce3, nonce3_);

        System.out.println("Authentication for client " + this.identity + " to " + resource_id + " has completed without errors");
        System.out.println("Shared Key Established:");
        System.out.println(resource_key);

    }

    //Prepares and sends back an encrypted nonce for later verification
    public void initial_request(ClientSocketS client, Packet packet) throws SocketError, CipherError, ResourceError, MessageError {

        int en_mode = packet.protocol_mode;
        int proto_version = packet.protocol_version;

        packet.generateFields();
        String resource_id = new String(packet.fields.get(1).bytes);

        packet.print_packet("Received Packet (Message pre-1); HELO, Identity from: " + resource_id);

        Truple<SecretKey> keys = store.get_keys(KDC);
        Cipher3DES cipher = new Cipher3DES(keys, ENCRYPT_MODE, en_mode);

        packet = new Packet(proto_version, en_mode, Packet.RESPONSE);

        byte[] nonce = Nonces.generateNonce();

        map.put(resource_id, nonce);

        //encrypt the nonce and send it on its way
        nonce = cipher.encrypt(nonce);

        packet.addField(nonce);
        packet.addField(identity.getBytes());
        packet.pack();

        packet.print_packet("Sending Packet (Message pre-2); enc_B(nonce_B) to: " + resource_id);
        client.send_pkt(packet);

    }

    /*
         Some uninteresting methods (accessor and setters)
     */
    //adds a private key to the client
    public void addPrivateKey(String pk) {
        private_key = new BigInteger(pk);
    }

    //sets the encryption mode for this client - CBC/EBC 3DES
    public void setMode(int mode) {
        this.mode = mode;
    }

    //sets the version for this client - EXTENDED_SCH or ORIGINAL_SCH
    public void setVersion(int version) {
        this.version = version;
    }

    public void close() {
        active.set(false);
    }

}
