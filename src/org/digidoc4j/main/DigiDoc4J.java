package org.digidoc4j.main;

import org.digidoc4j.Container;
import org.digidoc4j.Signer;
import org.digidoc4j.utils.PKCS12Signer;

/**
 * Client commandline tool for DigiDoc4J library.
 */
public final class DigiDoc4J {

  private DigiDoc4J() {

  }

  /**
   * @param args args for main method. No arguments are actually used
   * @throws Exception throws exception if the command cannot be executed successfully
   */
  public static void main(String[] args) throws Exception {
    Container container = new Container();
    container.addDataFile("test.txt", "text/plain");
    Signer pkcs12Signer = new PKCS12Signer("signout.p12", "test");
    container.sign(pkcs12Signer);
    container.save("doc.bdoc");
  }
}

