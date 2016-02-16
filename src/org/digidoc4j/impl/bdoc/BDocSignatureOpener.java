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

import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.bdoc.xades.XadesSignature;
import org.digidoc4j.impl.bdoc.xades.XadesSignatureParser;
import org.digidoc4j.impl.bdoc.xades.XadesSignatureValidator;
import org.digidoc4j.impl.bdoc.xades.XadesValidationDssFacade;
import org.digidoc4j.impl.bdoc.xades.XadesValidationReportGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class BDocSignatureOpener {

  private final static Logger logger = LoggerFactory.getLogger(BDocSignatureOpener.class);
  private final List<DSSDocument> detachedContents;
  private SignedDocumentValidator validator;
  private Configuration configuration;
  private XadesSignatureParser xadesSignatureParser = new XadesSignatureParser();
  private XadesValidationDssFacade validationDssFacade;

  public BDocSignatureOpener(List<DSSDocument> detachedContents, Configuration configuration) {
    this.configuration = configuration;
    this.detachedContents = detachedContents;
    validationDssFacade = new XadesValidationDssFacade(detachedContents, configuration);
  }

  public List<BDocSignature> parse(DSSDocument xadesDocument) {
    logger.debug("Parsing xades document");
    List<BDocSignature> signatures = new ArrayList<>();
    List<AdvancedSignature> signatureList = openXadesSignatureList(xadesDocument);
    for (AdvancedSignature advancedSignature : signatureList) {
      BDocSignature bDocSignature = createBDocSignature((XAdESSignature) advancedSignature, xadesDocument);
      bDocSignature.setSignatureDocument(xadesDocument);
      signatures.add(bDocSignature);
    }
    return signatures;
  }

  private BDocSignature createBDocSignature(XAdESSignature xAdESSignature, DSSDocument xadesDocument) {
    XadesSignature signature = xadesSignatureParser.parse(xAdESSignature);
    XadesValidationReportGenerator xadesReportGenerator = new XadesValidationReportGenerator(xadesDocument, detachedContents, configuration);
    xadesReportGenerator.setValidator(validator);
    XadesSignatureValidator xadesValidator = new XadesSignatureValidator(xadesReportGenerator, xAdESSignature, signature, configuration);
    return new BDocSignature(signature, xadesValidator);
  }

  private List<AdvancedSignature> openXadesSignatureList(DSSDocument signature) {
    validator = validationDssFacade.openXadesValidator(signature);
    List<AdvancedSignature> signatureList = validator.getSignatures();
    return signatureList;
  }
}
