/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/
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

    Container container = Container.create();
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
