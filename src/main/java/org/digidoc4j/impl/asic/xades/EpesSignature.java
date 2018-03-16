/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.xades;

import org.digidoc4j.SignatureProfile;

/**
 * EPES signature
 */
public class EpesSignature extends BesSignature {

  /**
   * @param xadesReportGenerator XADES validation report generator
   */
  public EpesSignature(XadesValidationReportGenerator xadesReportGenerator) {
    super(xadesReportGenerator);
  }

  @Override
  public SignatureProfile getProfile() {
    return SignatureProfile.B_EPES;
  }
  
}
