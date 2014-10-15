package prototype.samples;

import org.digidoc4j.Container;
import org.digidoc4j.signers.PKCS12Signer;

import java.io.*;

public class SerializeExample {

  public static void main(String[] args) throws IOException, ClassNotFoundException {
    serialize();
    deserializer();
  }

  private static void serialize() throws IOException {
    System.setProperty("digidoc4j.mode", "TEST");
    //Configuration configuration = new Configuration(Configuration.Mode.TEST);

    Container container = Container.create();
    //container.setConfiguration(configuration);
    container.addDataFile("testFiles/test.txt", "text/plain");

    FileOutputStream fileOut = new FileOutputStream("container.bin");
    ObjectOutputStream out = new ObjectOutputStream(fileOut);
    out.writeObject(container);
    out.flush();
    out.close();
    fileOut.close();
  }

  private static void deserializer() throws IOException, ClassNotFoundException {
    FileInputStream fileIn = new FileInputStream("container.bin");
    ObjectInputStream in = new ObjectInputStream(fileIn);

    Container container = (Container) in.readObject();

    container.sign(new PKCS12Signer("testFiles/signout.p12", "test".toCharArray()));
    container.save("SerializeExample.bdoc");

    in.close();
    fileIn.close();
  }
}
