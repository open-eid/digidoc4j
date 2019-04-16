/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.asice;

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
  Class for converting Xades signature to ASiCE signature.
 */
public class AsicESignatureOpener implements AsicSignatureOpener {

  private final static Logger logger = LoggerFactory.getLogger(AsicESignatureOpener.class);
  private Configuration configuration;

  /**
   * Constructor
   *
   * @param configuration configuration
   */
  public AsicESignatureOpener(Configuration configuration) {
    this.configuration = configuration;
  }

  /**
   * Xades signature wrapper opening method.
   * @param signatureWrapper wrapper containing signature document and it's xades signature
   * @return ASiCE signature
   */
  @Override
  public AsicSignature open(XadesSignatureWrapper signatureWrapper) {
    logger.debug("Opening xades signature");
    return createAsicESignature(signatureWrapper);
  }

  private AsicESignature createAsicESignature(XadesSignatureWrapper signatureWrapper) {
    XadesSignatureValidator xadesValidator = createSignatureValidator(signatureWrapper.getSignature());
    AsicESignature asicESignature = new AsicESignature(signatureWrapper.getSignature(), xadesValidator);
    asicESignature.setSignatureDocument(signatureWrapper.getSignatureDocument());
    return asicESignature;
  }

  private XadesSignatureValidator createSignatureValidator(XadesSignature signature) {
    XadesSignatureValidatorFactory validatorFactory = new XadesSignatureValidatorFactory();
    validatorFactory.setConfiguration(configuration);
    validatorFactory.setSignature(signature);
    XadesSignatureValidator xadesValidator = validatorFactory.create();
    return xadesValidator;
  }
}
