package SDC;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface Protocol extends Remote {
    String getAESKey() throws RemoteException;
    SDCService.RSAKeys getRSAKeys() throws RemoteException;
    String getVernamKey() throws RemoteException;

}
