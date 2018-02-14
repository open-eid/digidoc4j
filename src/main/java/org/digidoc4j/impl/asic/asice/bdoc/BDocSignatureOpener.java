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

import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.XadesSignatureParser;
import org.digidoc4j.impl.asic.xades.XadesValidationReportGenerator;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidatorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

/**
 * BDOC signature opener
 */
public class BDocSignatureOpener {

  private final static Logger logger = LoggerFactory.getLogger(BDocSignatureOpener.class);
  private final List<DSSDocument> detachedContents;
  private Configuration configuration;
  private XadesSignatureParser xadesSignatureParser = new XadesSignatureParser();

  /**
   * @param detachedContents list of detached content
   * @param configuration configuration
   */
  public BDocSignatureOpener(List<DSSDocument> detachedContents, Configuration configuration) {
    this.configuration = configuration;
    this.detachedContents = detachedContents;
  }

  /**
   * @param xadesDocument XADES document
   * @return list of BDOC signatures
   */
  public List<BDocSignature> parse(DSSDocument xadesDocument) {
    logger.debug("Parsing xades document");
    List<BDocSignature> signatures = new ArrayList<>(1);
    BDocSignature bDocSignature = createBDocSignature(xadesDocument);
    signatures.add(bDocSignature);
    return signatures;
  }

  private BDocSignature createBDocSignature(DSSDocument xadesDocument) {
    XadesValidationReportGenerator xadesReportGenerator = new XadesValidationReportGenerator(xadesDocument, detachedContents, configuration);
    XadesSignature signature = xadesSignatureParser.parse(xadesReportGenerator);
    XadesSignatureValidator xadesValidator = createSignatureValidator(signature);
    BDocSignature bDocSignature = new BDocSignature(signature, xadesValidator);
    bDocSignature.setSignatureDocument(xadesDocument);
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
