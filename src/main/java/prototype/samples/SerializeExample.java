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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.signers.PKCS12SignatureToken;

public class SerializeExample {

  public static void main(String[] args) throws IOException, ClassNotFoundException {
    serialize();
    deserializer();
  }

  private static void serialize() throws IOException {
    System.setProperty("digidoc4j.mode", "TEST");

    Container container = ContainerBuilder.
        aContainer().
        withDataFile("testFiles/test.txt", "text/plain").
        build();
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

    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(new PKCS12SignatureToken("testFiles/signout.p12", "test".toCharArray())).
        invokeSigning();
    container.addSignature(signature);
    container.saveAsFile("SerializeExample.bdoc");

    in.close();
    fileIn.close();
  }
}
