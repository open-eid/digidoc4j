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
  private SignedDocumentValidator validator;
  private List<DSSDocument> detachedContents;
  private Configuration configuration;
  private XadesSignatureParser xadesSignatureParser = new XadesSignatureParser();
  private CertificateVerifier certificateVerifier;

  public BDocSignatureOpener(List<DSSDocument> detachedContents, Configuration configuration) {
    this.detachedContents = detachedContents;
    this.configuration = configuration;
    certificateVerifier = createCertificateVerifier();
  }

  public List<BDocSignature> parse(DSSDocument xadesDocument) {
    List<BDocSignature> signatures = new ArrayList<>();
    List<AdvancedSignature> signatureList = openXadesSignatureList(xadesDocument);
    for (AdvancedSignature advancedSignature : signatureList) {
      BDocSignature bDocSignature = createBDocSignature((XAdESSignature) advancedSignature);
      bDocSignature.setSignatureDocument(xadesDocument);
      signatures.add(bDocSignature);
    }
    return signatures;
  }

  private BDocSignature createBDocSignature(XAdESSignature xAdESSignature) {
    XadesSignature signature = xadesSignatureParser.parse(xAdESSignature);
    XadesValidationReportGenerator xadesReportGenerator = new XadesValidationReportGenerator(validator, configuration.getValidationPolicy());
    XadesSignatureValidator xadesValidator = new XadesSignatureValidator(xadesReportGenerator, xAdESSignature, signature, configuration);
    return new BDocSignature(signature, xadesValidator);
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

  private CertificateVerifier createCertificateVerifier() {
    logger.debug("Creating new certificate verifier");
    CertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();
    certificateVerifier.setCrlSource(null); //Disable CRL checks
    certificateVerifier.setSignatureCRLSource(null); //Disable CRL checks
    logger.debug("Setting trusted cert source to the certificate verifier");
    certificateVerifier.setTrustedCertSource(configuration.getTSL());
    logger.debug("Finished creating certificate verifier");
    return certificateVerifier;
  }
}
