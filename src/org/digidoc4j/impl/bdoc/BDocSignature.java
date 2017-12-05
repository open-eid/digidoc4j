/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import org.digidoc4j.impl.bdoc.asic.AsicESignature;
import org.digidoc4j.impl.bdoc.xades.XadesSignature;
import org.digidoc4j.impl.bdoc.xades.validation.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BDoc signature implementation.
 */
public class BDocSignature extends AsicESignature {

  private static final Logger logger = LoggerFactory.getLogger(BDocSignature.class);

  /**
   * BDoc signature constructor.
   *
   * @param xadesSignature
   * @param validator
   */
  public BDocSignature(XadesSignature xadesSignature, SignatureValidator validator) {
    super(xadesSignature, validator);
    logger.debug("New BDoc signature created");
  }


}
