package Simulation;

import Cipher.CipherError;
import Msg.MessageError;
import Nodes.Client;
import Nodes.ResourceError;
import static Simulation.PubKeys.Bob;
import static Simulation.PubKeys.KDC;
import Sockets.SocketError;

public class BClient {

    //private key ( generated using CipherRSA )
    protected static String prk = "8879615993307052660307648829078020099353144832136172935648487317494389288824444680505952728536517945446240999417044084808446491226615888089088040899214501097256367428389307552729098750756742835285440002570756289634897513952207464873764945018642824512179375105440218921565649418290568635051089766032592336885418929622984259584571558628150623956884463552915404767223620709163082642207357962632161232774729465112889660601495523839152110439541645198617129338132932393947176455357880637225242845940664949864110090133649268367953830964250574992283860269723428798245365807723397224810718094024299522230194465761871726982187";

    //bootstrap for this client ( the only difference in these subclasses of clients is the private key and identity)
    public static void main(String[] args) {
        try {
            Client bob = new Client(Bob);
     
            //script to setup Bob to listen after authenticating w/ the KDC
            System.out.println("Adding Private Key....");
            bob.addPrivateKey(prk);
            System.out.println("Contacting KDC on port 3030 for initial key establishment.....");
            bob.authenticateKDC("localhost", 3030, KDC);
            System.out.println("Setting up Server and listening on port 5050.......");
            bob.setupServer(5050); // setup the server for later(alice will contact bob at some point)
        } catch (ResourceError | SocketError | MessageError | CipherError ex) {
            System.err.println(ex.getMessage());
        }
    }
}
