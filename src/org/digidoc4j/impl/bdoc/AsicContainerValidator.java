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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.bdoc.manifest.ManifestValidator;
import org.digidoc4j.impl.bdoc.xades.XadesSignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.asic.validation.ASiCContainerValidator;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

@Deprecated
public class AsicContainerValidator implements Serializable {

  private final static Logger logger = LoggerFactory.getLogger(AsicContainerValidator.class);
  private DSSDocument signedDocument;
  private CertificateVerifier certificateVerifier;
  private Configuration configuration;
  private DigestAlgorithm containerDigestAlgorithm;
  private List<Signature> signatures = new ArrayList<>();
  private Map<String, List<DigiDoc4JException>> signatureVerificationErrors = new LinkedHashMap<>();
  private transient Reports validationReport;

  public AsicContainerValidator(DSSDocument asicContainer, CertificateVerifier certificateVerifier, Configuration configuration) {
    this.signedDocument = asicContainer;
    this.certificateVerifier = certificateVerifier;
    this.configuration = configuration;
  }

  public AsicContainerValidationResult validate() {
    logger.debug("Validating asic container");
    try {
      SignedDocumentValidator validator = openValidator();
      loadSignatures(validator);
      List<String> manifestErrors = new ManifestValidator(validator).validateDocument();
      ValidationResultForBDoc bDocValidationResult = new ValidationResultForBDoc(validationReport, signatures, manifestErrors, signatureVerificationErrors);
      AsicContainerValidationResult validationResult = createContainerValidationResult();
      validationResult.setbDocValidationResult(bDocValidationResult);
      return validationResult;
    } catch (DSSException e) {
      logger.error("Error validating container: " + e.getMessage());
      throw new TechnicalException("Error validating container: " + e.getMessage(), e);
    }
  }

  public AsicContainerValidationResult loadContainerDetails() {
    logger.debug("Loading container details");
    SignedDocumentValidator validator = openValidator();
    loadSignatures(validator);
    AsicContainerValidationResult validationResult = createContainerValidationResult();
    Map<String, DataFile> dataFiles = new BDocDataFilesLoader(validator).loadDataFiles();
    validationResult.setDataFiles(dataFiles);
    return validationResult;
  }

  public List<Signature> loadSignaturesWithoutValidation() {
    logger.debug("Loading signatures without validation");
    signatures = new ArrayList<>();
    SignedDocumentValidator validator = openValidator();
    validate(validator);
    List<AdvancedSignature> signatureList = validator.getSignatures();
    for (AdvancedSignature advancedSignature : signatureList) {
      signatures.add(new BDocSignature(null, null));
    }
    return signatures;
  }

  public XAdESSignature findXadesSignature(String deterministicId) throws SignatureNotFoundException {
    logger.debug("Finding xades signature with id " + deterministicId);
    SignedDocumentValidator validator = openValidator();
    validate(validator);
    List<AdvancedSignature> signatureList = validator.getSignatures();
    for (AdvancedSignature advancedSignature : signatureList) {
      if (advancedSignature.getId().equals(deterministicId)) {
        logger.debug("Signature found");
        return (XAdESSignature) advancedSignature;
      }
    }
    logger.error("Signature " + deterministicId + " was not found");
    throw new SignatureNotFoundException();
  }

  private void loadSignatures(SignedDocumentValidator validator) {
    logger.debug("Loading signatures");
    signatureVerificationErrors = new LinkedHashMap<>();
    loadValidationResults(validator);
    List<AdvancedSignature> signatureList = validator.getSignatures();
    for (AdvancedSignature advancedSignature : signatureList) {
      /*
      XadesSignatureValidator signatureValidator = new XadesSignatureValidator(validationReport, (XAdESSignature) advancedSignature, configuration);
      BDocSignature signature = signatureValidator.extractValidatedSignature();
      signatureVerificationErrors.put(signature.getId(), signature.getValidationErrors());
      signatures.add(signature);
      */
    }
  }

  private SignedDocumentValidator openValidator() {
    try {
      return ASiCContainerValidator.fromDocument(signedDocument);
    } catch (DSSException e) {
      logger.error("Error validating container: " + e.getMessage());
      throw new TechnicalException("Error validating container: " + e.getMessage(), e);
    }
  }

  private void loadValidationResults(SignedDocumentValidator validator) {
    validate(validator);
    containerDigestAlgorithm = validationReport.getDiagnosticData().getSignatureDigestAlgorithm();
  }

  private Reports validate(SignedDocumentValidator validator) {
    logger.debug("Validator: " + validator);
    if (validationReport != null) {
      logger.debug("Using existing validation report");
      return validationReport;
    }
    validationReport = createNewValidationReport(validator);
    printReport(validationReport);
    return validationReport;
  }

  private Reports createNewValidationReport(SignedDocumentValidator validator) {
    try {
      logger.debug("Creating a new validation report");
      prepareValidator(validator);
      InputStream validationPolicyAsStream = getValidationPolicyAsStream();
      return validator.validateDocument(validationPolicyAsStream);
    } catch (DSSException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  private void prepareValidator(SignedDocumentValidator validator) {
    certificateVerifier.setOcspSource(null);
    certificateVerifier.setTrustedCertSource(configuration.getTSL());
    validator.setCertificateVerifier(certificateVerifier);
  }

  private InputStream getValidationPolicyAsStream() {
    String policyFile = configuration.getValidationPolicy();
    if (Files.exists(Paths.get(policyFile))) {
      try {
        return new FileInputStream(policyFile);
      } catch (FileNotFoundException ignore) {
        logger.warn(ignore.getMessage());
      }
    }
    return getClass().getClassLoader().getResourceAsStream(policyFile);
  }

  private AsicContainerValidationResult createContainerValidationResult() {
    AsicContainerValidationResult validationResult = new AsicContainerValidationResult();
    validationResult.setSignatures(signatures);
    validationResult.setContainerDigestAlgorithm(containerDigestAlgorithm);
    validationResult.setValidationReport(validationReport);
    return validationResult;
  }

  private void printReport(Reports report) {
    if(logger.isTraceEnabled()) {
      Reports currentReports = report;
      do {
        logger.trace("----------------Validation report---------------");
        logger.trace(currentReports.getDetailedReport().toString());

        logger.trace("----------------Simple report-------------------");
        logger.trace(currentReports.getSimpleReport().toString());

        currentReports = currentReports.getNextReports();
      } while (currentReports != null);
    }
  }
}
