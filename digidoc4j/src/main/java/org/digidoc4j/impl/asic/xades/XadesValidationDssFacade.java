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

import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

public class XadesValidationDssFacade {

  private final static Logger logger = LoggerFactory.getLogger(XadesValidationDssFacade.class);
  private List<DSSDocument> detachedContents;
  private Configuration configuration;
  private CertificateVerifier certificateVerifier;

  public XadesValidationDssFacade(List<DSSDocument> detachedContents, Configuration configuration) {
    this.detachedContents = detachedContents;
    this.configuration = configuration;
    certificateVerifier = createCertificateVerifier();
  }

  public SignedDocumentValidator openXadesValidator(DSSDocument signature) {
    try {
      logger.debug("Opening signature validator");
      SignedDocumentValidator validator = new XMLDocumentValidator(signature);
      logger.debug("Finished opening signature validator");
      validator.setDetachedContents(detachedContents);
      validator.setCertificateVerifier(certificateVerifier);
      SignaturePolicyProvider signaturePolicyProvider = Helper.getBdocSignaturePolicyProvider(signature);
      validator.setSignaturePolicyProvider(signaturePolicyProvider);
      return validator;
    } catch (DSSException e) {
      logger.error("Failed to parse xades signature: " + e.getMessage());
      throw new InvalidSignatureException();
    }
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
