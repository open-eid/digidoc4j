/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.signers;

import java.security.cert.X509Certificate;

import org.digidoc4j.SignatureToken;

/**
 * Signer for external services for example in web
 */
public abstract class ExternalSigner implements SignatureToken {

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
  public void close(){
    //Do nothing
  }

}
