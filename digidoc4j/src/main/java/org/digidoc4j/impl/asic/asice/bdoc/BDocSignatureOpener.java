/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asice.bdoc;

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.AsicSignature;
import org.digidoc4j.impl.asic.xades.AsicXadesSignatureOpener;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;

/**
 * BDOC signature opener
 */
public class BDocSignatureOpener extends AsicXadesSignatureOpener {

  /**
   * @param configuration configuration
   */
  public BDocSignatureOpener(Configuration configuration) {
    super(configuration);
  }

  @Override
  protected AsicSignature createAsicSignature(XadesSignature xadesSignature, XadesSignatureValidator xadesValidator) {
    return new BDocSignature(xadesSignature, xadesValidator);
  }

}
