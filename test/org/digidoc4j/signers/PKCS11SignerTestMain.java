package org.digidoc4j.signers;

import org.digidoc4j.Container;
import org.digidoc4j.Signer;

import java.security.NoSuchAlgorithmException;

public class PKCS11SignerTestMain {

  public static void signWithIDCard() throws NoSuchAlgorithmException {
    Container container = Container.create(Container.DocumentType.BDOC);
    Signer pkcs11Signer = new PKCS11Signer("01497".toCharArray());
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(pkcs11Signer);
    container.save("signWithIDCard.ddoc");
  }

  // must be run with parameter -Djava.security.debug=sunpkcs11,pkcs11
  public static void main(String[] args) throws NoSuchAlgorithmException {
    signWithIDCard();
  }
}