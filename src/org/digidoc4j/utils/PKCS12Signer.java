package org.digidoc4j.utils;

import eu.europa.ec.markt.dss.signature.token.Pkcs12SignatureToken;
import org.digidoc4j.api.Signer;

/**
 * Implements PKCS12 signer.
 */
public class PKCS12Signer extends Signer {


  /**
   * Constructs PKCS12 signer object. If more than one key is provided only first is used
   *
   * @param fileName .p12 file name and path
   * @param password keystore password
   */
  public PKCS12Signer(String fileName, String password) {
    signatureTokenConnection = new Pkcs12SignatureToken(password, fileName);
    keyEntry = signatureTokenConnection.getKeys().get(0);
 }
}
