/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades;

import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.bdoc.BDocSignature;
import org.digidoc4j.impl.bdoc.SKCommonCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class XadesSignatureParser {

  private final static Logger logger = LoggerFactory.getLogger(XadesSignatureParser.class);
  private List<DSSDocument> detachedContents;
  private SignedDocumentValidator validator;
  private Configuration configuration;
  private CertificateVerifier certificateVerifier;

  public XadesSignatureParser(List<DSSDocument> detachedContents, Configuration configuration) {
    this.detachedContents = detachedContents;
    this.configuration = configuration;
  }

  public List<BDocSignature> parse(DSSDocument signature) {
    logger.debug("Parsing XAdES signature");
    initCertificateVerifier();
    List<BDocSignature> signatures = new ArrayList<>();
    List<AdvancedSignature> signatureList = openXadesSignatureList(signature);
    for (AdvancedSignature advancedSignature : signatureList) {
      XAdESSignature xAdESSignature = (XAdESSignature) advancedSignature;

      XadesSignatureWrapper signatureWrapper = new XadesSignatureWrapper(xAdESSignature);
      XadesValidationReportGenerator xadesReportGenerator = new XadesValidationReportGenerator(validator, certificateVerifier, configuration);
      XadesSignatureValidator xadesValidator = new XadesSignatureValidator(xadesReportGenerator, signatureWrapper, configuration);

      BDocSignature bDocSignature = new BDocSignature(signatureWrapper, xadesValidator);

      signatures.add(bDocSignature);
    }
    return signatures;
  }

  private List<AdvancedSignature> openXadesSignatureList(DSSDocument signature) {
    logger.debug("Opening signature validator");
    validator = SignedDocumentValidator.fromDocument(signature);
    logger.debug("Finished opening signature validator");
    validator.setDetachedContents(detachedContents);
    validator.setCertificateVerifier(certificateVerifier);
    List<AdvancedSignature> signatureList = validator.getSignatures();
    return signatureList;
  }

  private void initCertificateVerifier() {
    certificateVerifier = new SKCommonCertificateVerifier();
    certificateVerifier.setCrlSource(null); //Disable CRL checks
    certificateVerifier.setSignatureCRLSource(null); //Disable CRL checks
    certificateVerifier.setTrustedCertSource(configuration.getTSL());
  }
}
