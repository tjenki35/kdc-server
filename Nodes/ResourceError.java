package Nodes;

public class ResourceError extends Exception {

    public ResourceError(String reason, Exception ex) {
        super(reason,ex);
    }
    
    public ResourceError(String reason){
        super(reason);
    }
    
}
