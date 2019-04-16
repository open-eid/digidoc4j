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
import org.digidoc4j.impl.asic.AsicSignatureOpener;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.XadesSignatureWrapper;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidatorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BDOC signature opener
 */
public class BDocSignatureOpener implements AsicSignatureOpener {

  private final static Logger logger = LoggerFactory.getLogger(BDocSignatureOpener.class);
  private Configuration configuration;

  /**
   * @param configuration configuration
   */
  public BDocSignatureOpener(Configuration configuration) {
    this.configuration = configuration;
  }

  /**
   * Xades signature wrapper opening method.
   * @param signatureWrapper wrapper containing signature document and it's xades signature
   * @return BDoc signature
   */
  @Override
  public AsicSignature open(XadesSignatureWrapper signatureWrapper) {
    logger.debug("Opening xades signature");
    return createBDocSignature(signatureWrapper);
  }

  private BDocSignature createBDocSignature(XadesSignatureWrapper signatureWrapper) {
    XadesSignatureValidator xadesValidator = createSignatureValidator(signatureWrapper.getSignature());
    BDocSignature bDocSignature = new BDocSignature(signatureWrapper.getSignature(), xadesValidator);
    bDocSignature.setSignatureDocument(signatureWrapper.getSignatureDocument());
    return bDocSignature;
  }

  private XadesSignatureValidator createSignatureValidator(XadesSignature signature) {
    XadesSignatureValidatorFactory validatorFactory = new XadesSignatureValidatorFactory();
    validatorFactory.setConfiguration(configuration);
    validatorFactory.setSignature(signature);
    XadesSignatureValidator xadesValidator = validatorFactory.create();
    return xadesValidator;
  }
}
