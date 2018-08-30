package Nodes;

import Cipher.Truple;
import Nodes.ResourceError;
import java.util.HashMap;
import javax.crypto.SecretKey;

public class KeyStore {

    //collection for pub keys object
    private final HashMap<String, Truple<SecretKey>> store;

    public KeyStore() {
        store = new HashMap<>();
    }

    public Truple<SecretKey> get_keys(String name) throws ResourceError {
        synchronized (store) {
            if (store.containsKey(name)) {
                return store.get(name);
            } else {
                throw new ResourceError("No Key for User: "+ name);
            }
        }
    }

    public void put(String name, Truple<SecretKey> keys) {
        synchronized (store) {
            store.put(name, keys);
        }
    }
}
