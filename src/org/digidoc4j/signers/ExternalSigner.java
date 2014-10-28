package org.digidoc4j.signers;

import org.digidoc4j.Signer;
import org.digidoc4j.exceptions.NotSupportedException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Signer for external services for example in web
 */
public abstract class ExternalSigner implements Signer {

  private X509Certificate signingCertificate;


  /**
   * Creates new external signer
   *
   * @param signingCertificate certificate used for signing
   */
  public ExternalSigner(X509Certificate signingCertificate) {
    this.signingCertificate = signingCertificate;
  }

  @Override
  public X509Certificate getCertificate() {
    return this.signingCertificate;
  }

  @Override
  public PrivateKey getPrivateKey() {
    throw new NotSupportedException("External signer does not have private key");
  }
}
