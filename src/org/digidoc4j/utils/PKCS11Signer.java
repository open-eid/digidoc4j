package org.digidoc4j.utils;

import eu.europa.ec.markt.dss.signature.token.Pkcs11SignatureToken;
import org.digidoc4j.api.Configuration;
import org.digidoc4j.api.Signer;

public class PKCS11Signer extends Signer {

  private final Configuration configuration;

  public PKCS11Signer(char[] password) {
    System.setProperty("java.security.debug", "sunpkcs11,pkcs11");

    configuration = new Configuration();
    signatureTokenConnection = new Pkcs11SignatureToken(configuration.getPKCS11ModulePath(), password, 1);
    keyEntry = signatureTokenConnection.getKeys().get(0);
  }

}
