package SDC;

import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;

public class Application {
    public static void main(String[] args) {
        try {
            final var sdc = new SDCService();
            final var skeleton = (Protocol) UnicastRemoteObject.exportObject(sdc, 0);
            LocateRegistry.createRegistry(SDCService.PORT);
            final var registry = LocateRegistry.getRegistry(SDCService.PORT);
            registry.bind("sdc", skeleton);
            System.out.println("serviço de distribuíção de chaves rodando em " + SDCService.PORT);
        } catch (RemoteException | AlreadyBoundException e) {
            throw new RuntimeException(e);
        }
    }
}
