package Nodes;

import Cipher.NonceError;
import Nodes.ResourceError;
import java.util.HashMap;

public class AuthMap {

    //collection for pub keys object
    private final HashMap<String, byte[]> map;

    public AuthMap() {
        map = new HashMap<>();
    }

    //removes from map after retrieval
    public byte[] get_mapped(String name) throws NonceError {
        synchronized (map) {
            if (map.containsKey(name)) {
                byte[] temp = map.get(name);
                map.remove(name);
                return temp;
            } else {
                throw new NonceError("No valid Nonce found in map, aborting");
            }
        }
    }

    public void put(String name, byte[] nonce) {
        synchronized (map) {
            map.put(name, nonce);
        }
    }
}
