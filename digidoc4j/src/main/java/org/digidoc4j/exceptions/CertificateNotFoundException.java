/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.exceptions;

/**
 * Certificate not found exception
 */
public class CertificateNotFoundException extends DigiDoc4JException {

  /**
   * @param message error message
   * @param signatureId id of signature
   */
  public CertificateNotFoundException(String message, String signatureId) {
    super(message, signatureId);
  }

}
