package Simulation;

import static Cipher.Cipher3DES.CBC;
import static Cipher.Cipher3DES.ECB;
import Cipher.CipherError;
import Cipher.NonceError;
import Msg.MessageError;
import static Msg.Packet.EXTENDED_SCH;
import static Msg.Packet.ORIGINAL_SCH;
import Nodes.Client;
import Nodes.ProtocolError;
import Nodes.ResourceError;
import static Simulation.PubKeys.Alice;
import static Simulation.PubKeys.Bob;
import static Simulation.PubKeys.KDC;
import Sockets.SocketError;

/**
 * Extension of Client for the simulation *( this appliaction of the class is a
 * script to request a ticket for authentication ) **( note that this is done
 * after this client establishes a key between itself and the KDC )
 */
public class AClient {

    //private key ( generated using CipherRSA )
    private static final String PK = "17885697266445385250671023187600486281293988318291496367370126373581755973673880820098970546392088906341851471514523981115771390764277928481320245823049040478507378609655562215089590263658222829290634237522102918614382891944442353224233113530830557376123140919625462949723992020480386464328727515646765168052955700606198329771779099291033685186040109445839263233045802897200937627710994580514505145902876279280159309262755368608048531627422820203046537723297098109155047005399674644327103891994834453747217484696260754151338276222473720420940614069436582637406156655632236150263007777422751277603400165285015766700143";

    //bootstrap for this client ( the only difference in these subclasses of clients is the private key and identity)
    public static void main(String[] args) {

        try {
            
            //this client accepts the command switches ( -EX/-OR and -ECB/-CBC )
            Client alice = new Client(Alice);
            if (args.length > 0) {
                if (args[0].equals("-EX")) {
                    System.out.println("Version : Extended Sch. ");
                    alice.setVersion(EXTENDED_SCH);
                } else if (args[0].equals("-OR")) {
                    alice.setVersion(ORIGINAL_SCH);
                    System.out.println("Version : Original Sch. ");
                }
                if (args.length > 1) {
                    if (args[1].equals("-ECB")) {
                        System.out.println("Mode : ECB");
                        alice.setMode(ECB);
                    } else if (args[1].equals("-CBC")) {
                        System.out.println("Mode : CBC");
                        alice.setMode(CBC);
                    }
                }
            }

            System.out.println("Adding Private Key....");
            alice.addPrivateKey(PK);

            System.out.println("Contacting KDC on port 3030 for initial key establishment.....");
            alice.authenticateKDC("localhost", 3030, KDC);
            if (args.length > 0 && args[0].equals("-EX")) {
                System.out.println("Requesting nonce from Bob.....");
                alice.requestNonce("localhost", 5050);
            }
            System.out.println("Requesting Ticket from the KDC......");
            byte[] ticket = alice.requestTicket(Bob, "localhost", 3030, KDC);
            System.out.println("Authenticating w/ Bob.....");
            alice.authenticate("localhost", 5050, Bob, ticket);

        } catch (SocketError | ResourceError | MessageError | CipherError | ProtocolError | NonceError ex) {
            System.err.println(ex.getMessage());
        }
    }
}
