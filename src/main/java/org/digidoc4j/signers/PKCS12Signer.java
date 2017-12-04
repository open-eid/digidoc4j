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

/**
 * This class has been renamed to PKCS12SignatureToken. Use {@link PKCS12SignatureToken} instead.
 * @deprecated
 */
@Deprecated
public class PKCS12Signer extends PKCS12SignatureToken {

  /**
   * This class has been renamed to PKCS12SignatureToken. Use {@link PKCS12SignatureToken} instead.
   * @deprecated
   */
  @Deprecated
  public PKCS12Signer(String fileName, char[] password) {
    super(fileName, password);
  }
}
