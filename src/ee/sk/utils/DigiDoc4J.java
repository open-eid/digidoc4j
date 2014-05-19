package ee.sk.utils;

import ee.sk.digidoc4j.Container;
import ee.sk.digidoc4j.Signer;
import ee.sk.digidoc4j.utils.PKCS12Signer;

/**
 * Client commandline utility for DigiDoc4J library
 */
public class DigiDoc4J {
  public static void main(String[] args) throws Exception {
    Container container = new Container();
    container.addDataFile("test.txt", "text/plain");
    Signer pkcs12Signer = new PKCS12Signer("signout.p12", "test");
    container.sign(pkcs12Signer);
    container.save("doc.bdoc");
  }
}
