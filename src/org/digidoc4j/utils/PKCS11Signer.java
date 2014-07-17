package org.digidoc4j.utils;

import eu.europa.ec.markt.dss.signature.token.Pkcs11SignatureToken;
import org.digidoc4j.api.Configuration;
import org.digidoc4j.api.Signer;

/**
 * This signer implementation is for testing purposes
 */
@Deprecated
public class PKCS11Signer extends Signer {

  public PKCS11Signer(char[] password) {
    Configuration configuration = new Configuration();
    signatureTokenConnection = new Pkcs11SignatureToken(configuration.getPKCS11ModulePath(), password, 2);
    keyEntry = signatureTokenConnection.getKeys().get(0);
  }

}
