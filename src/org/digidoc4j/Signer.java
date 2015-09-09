/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

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
  X509Certificate getCertificate();

  /**
   * Retrieves private key
   *
   * @return private key
   */
  PrivateKey getPrivateKey();

  /**
   * There must be implemented routines needed for signing
   *
   * @param digestAlgorithm  provides needed information for signing
   * @param dataToSign data to sign
   * @return signature raw value
   */
  byte[] sign(DigestAlgorithm digestAlgorithm, byte[] dataToSign);

}
