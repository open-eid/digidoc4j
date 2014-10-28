package org.digidoc4j;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Abstract class providing signing interface
 */
public interface Signer {

  /**
   * Returns signer certificate
   *
   * @return signer certificate
   */
  public abstract X509Certificate getCertificate();

  /**
   * Retrieves private key
   *
   * @return private key
   */
  public abstract PrivateKey getPrivateKey();

  /**
   * There must be implemented routines needed for signing
   *
   * @param container  provides needed information for signing
   * @param dataToSign data to sign
   * @return signature raw value
   */
  public abstract byte[] sign(Container container, byte[] dataToSign);

}
