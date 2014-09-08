package prototype;

import org.digidoc4j.api.Configuration;
import org.digidoc4j.api.Container;
import org.digidoc4j.signers.PKCS12Signer;

/**
 * Prototype for testing purposes
 */
public final class Prototype {

  private Prototype() {

  }

  /**
   * Main method
   *
   * @param args command line arguments
   */
  public static void main(String[] args) {
    Container container = Container.create();
    container.setConfiguration(new Configuration(Configuration.Mode.TEST));
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(new PKCS12Signer("testFiles/signout.p12", "test".toCharArray()));
    container.sign(new PKCS12Signer("testFiles/signout.p12", "test".toCharArray()));
    container.save("prototype.bdoc");
  }
}
