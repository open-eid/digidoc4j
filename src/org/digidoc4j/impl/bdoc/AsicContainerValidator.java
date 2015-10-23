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

import static org.apache.commons.lang.StringUtils.isBlank;

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

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Signature;
import org.digidoc4j.exceptions.CertificateRevokedException;
import org.digidoc4j.exceptions.ContainerWithoutSignaturesException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidTimestampException;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignaturePolicy;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCContainerValidator;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.rules.MessageTag;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

public class AsicContainerValidator implements Serializable {

  private final static Logger logger = LoggerFactory.getLogger(AsicContainerValidator.class);
  private static final String TM_POLICY = "urn:oid:1.3.6.1.4.1.10015.1000.3.2.1";
  private static final String OIDAS_URN = "OIDAsURN";
  private static final String XADES_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";
  private DSSDocument signedDocument;
  private CertificateVerifier certificateVerifier;
  private Configuration configuration;
  private DigestAlgorithm containerDigestAlgorithm;
  private List<Signature> signatures = new ArrayList<>();
  private Map<String, List<DigiDoc4JException>> additionalVerificationErrors = new LinkedHashMap<>();
  private transient Reports validationReport;

  public AsicContainerValidator(DSSDocument asicContainer, CertificateVerifier certificateVerifier, Configuration configuration) {
    this.signedDocument = asicContainer;
    this.certificateVerifier = certificateVerifier;
    this.configuration = configuration;
  }

  public AsicContainerValidationResult validate() throws ContainerWithoutSignaturesException {
    logger.debug("Validating asic container");
    try {

      SignedDocumentValidator validator = openValidator();
      loadSignatures(validator);

      List<String> manifestErrors = new ManifestValidator(validator).validateDocument(signatures);
      ValidationResultForBDoc bDocValidationResult = new ValidationResultForBDoc(validationReport, signatures, manifestErrors, additionalVerificationErrors);

      AsicContainerValidationResult validationResult = createContainerValidationResult();
      validationResult.setbDocValidationResult(bDocValidationResult);
      validationResult.setSignedDocuments(validator.getDetachedContents());
      return validationResult;
    } catch (DSSException e) {
      if (StringUtils.equalsIgnoreCase("This is not an ASiC container. The signature cannot be found!", e.getMessage())) {
        throw new ContainerWithoutSignaturesException();
      }
      logger.error("Error validating container: " + e.getMessage());
      throw new TechnicalException("Error validating container: " + e.getMessage(), e);
    }
  }

  public AsicContainerValidationResult loadContainerDetails() throws ContainerWithoutSignaturesException {
    logger.debug("Loading container details");
    SignedDocumentValidator validator = openValidator();
    loadSignatures(validator);
    AsicContainerValidationResult validationResult = createContainerValidationResult();
    validationResult.setSignedDocuments(validator.getDetachedContents());
    return validationResult;
  }

  public List<Signature> loadSignaturesWithoutValidation() throws ContainerWithoutSignaturesException {
    logger.debug("Loading signatures without validation");
    signatures = new ArrayList<>();
    SignedDocumentValidator validator = openValidator();
    validate(validator);

    List<AdvancedSignature> signatureList = validator.getSignatures();
    for (AdvancedSignature advancedSignature : signatureList) {
      signatures.add(new BDocSignature((XAdESSignature) advancedSignature));
    }

    return signatures;
  }

  public XAdESSignature findXadesSignature(String deterministicId) throws SignatureNotFoundException, ContainerWithoutSignaturesException {
    logger.debug("Finding xades signature with id " + deterministicId);
    logger.debug("Id: " + deterministicId);
    SignedDocumentValidator validator = openValidator();
    validate(validator);
    List<AdvancedSignature> signatureList = validator.getSignatures();
    for (AdvancedSignature advancedSignature : signatureList) {
      if (advancedSignature.getId().equals(deterministicId)) {
        logger.debug("Signature found");
        return (XAdESSignature) advancedSignature;
      }
    }
    SignatureNotFoundException exception = new SignatureNotFoundException();
    logger.info(exception.getMessage());
    throw exception;
  }

  private InputStream getValidationPolicyAsStream(String policyFile) {
    logger.debug("");
    if (Files.exists(Paths.get(policyFile))) {
      try {
        return new FileInputStream(policyFile);
      } catch (FileNotFoundException ignore) {
        logger.warn(ignore.getMessage());
      }
    }

    return getClass().getClassLoader().getResourceAsStream(policyFile);
  }

  private Map<String, SimpleReport> loadValidationResults(SignedDocumentValidator validator) {
    logger.debug("");
    Map<String, SimpleReport> simpleReports = new LinkedHashMap<>();

    Reports report = validate(validator);

    containerDigestAlgorithm = report.getDiagnosticData().getSignatureDigestAlgorithm();

    do {
      SimpleReport simpleReport = report.getSimpleReport();
      if (simpleReport.getSignatureIdList().size() > 0)
        simpleReports.put(simpleReport.getSignatureIdList().get(0), simpleReport);
      report = report.getNextReports();
    } while (report != null);
    return simpleReports;
  }

  private Reports validate(SignedDocumentValidator validator) {
    logger.debug("Validator: " + validator);
    if (validationReport != null) {
      return validationReport;
    }

    certificateVerifier.setOcspSource(null);

    TrustedListsCertificateSource trustedCertSource = configuration.getTSL();

    certificateVerifier.setTrustedCertSource(trustedCertSource);
    validator.setCertificateVerifier(certificateVerifier);

    try {
      String validationPolicy = configuration.getValidationPolicy();
      InputStream validationPolicyAsStream = getValidationPolicyAsStream(validationPolicy);
      validationReport = validator.validateDocument(validationPolicyAsStream);
      printReport(validationReport);
      return validationReport;
    } catch (DSSException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  private void loadSignatures(SignedDocumentValidator validator) {
    logger.debug("");
    Map<String, SimpleReport> simpleReports = loadValidationResults(validator);
    List<AdvancedSignature> signatureList = validator.getSignatures();

    additionalVerificationErrors = new LinkedHashMap<>();
    for (AdvancedSignature advancedSignature : signatureList) {
      List<DigiDoc4JException> validationErrors = new ArrayList<>();
      String reportSignatureId = advancedSignature.getId();
      additionalVerificationErrors.put(reportSignatureId, validatePolicy(advancedSignature));
      DigiDoc4JException referenceError = validateSignedPropertiesReference(advancedSignature);
      if (referenceError != null)
        additionalVerificationErrors.get(reportSignatureId).add(referenceError);
      SimpleReport simpleReport = getSimpleReport(simpleReports, reportSignatureId);
      if (simpleReport != null) {
        for (Conclusion.BasicInfo error : simpleReport.getErrors(reportSignatureId)) {
          String errorMessage = error.toString();
          logger.info(errorMessage);
          if(errorMessage.contains(MessageTag.BBB_XCV_ISCR_ANS.getMessage()))
            validationErrors.add(new CertificateRevokedException(errorMessage));
          else
            validationErrors.add(new DigiDoc4JException(errorMessage));
        }
      }
      validationErrors.addAll(additionalVerificationErrors.get(reportSignatureId));
      addTimestampErrors(validationErrors, reportSignatureId);
      signatures.add(new BDocSignature((XAdESSignature) advancedSignature, validationErrors));
    }
  }

  private void addTimestampErrors(List<DigiDoc4JException> validationErrors, String signatureId) {
    if(!isTimestampValidForSignature(signatureId)) {
      logger.error("Signature " + signatureId + " has an invalid timestamp");
      validationErrors.add(new InvalidTimestampException("Signature " + signatureId + " has an invalid timestamp"));
    }
  }

  private boolean isTimestampValidForSignature(String signatureId) {
    logger.debug("Finding timestamp errors for signature " + signatureId);
    DiagnosticData diagnosticData = validationReport.getDiagnosticData();
    if (diagnosticData == null) {
      return true;
    }
    List<String> timestampIdList = diagnosticData.getTimestampIdList(signatureId);
    if(timestampIdList == null || timestampIdList.isEmpty()) {
      return true;
    }
    String timestampId = timestampIdList.get(0);
    return diagnosticData.isTimestampMessageImprintIntact(timestampId);
  }

  private List<DigiDoc4JException> validatePolicy(AdvancedSignature advancedSignature) {
    logger.debug("");
    ArrayList<DigiDoc4JException> validationErrors = new ArrayList<>();
    SignaturePolicy policy = advancedSignature.getPolicyId();
    if (policy != null) {
      String policyIdentifier = policy.getIdentifier().trim();
      if (!TM_POLICY.equals(policyIdentifier)) {
        validationErrors.add(new DigiDoc4JException("Wrong policy identifier: " + policyIdentifier));
        return validationErrors;
      }
      if (isBlank(policy.getUrl()))
        validationErrors.add(new DigiDoc4JException("Policy url is missing for identifier: " + policyIdentifier));

      XPathQueryHolder xPathQueryHolder = ((XAdESSignature) advancedSignature).getXPathQueryHolder();
      Element signatureElement = ((XAdESSignature) advancedSignature).getSignatureElement();
      Element element = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER);
      Element identifier = DSSXMLUtils.getElement(element,
          "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier");
      if (!OIDAS_URN.equals(identifier.getAttribute("Qualifier"))) {
        validationErrors.add(new DigiDoc4JException("Wrong policy identifier qualifier: "
            + identifier.getAttribute("Qualifier")));
      }
    }

    return validationErrors;
  }

  private DigiDoc4JException validateSignedPropertiesReference(AdvancedSignature advancedSignature) {
    logger.debug("");
    List<Element> signatureReferences = ((XAdESSignature) advancedSignature).getSignatureReferences();
    int nrOfSignedPropertiesReferences = 0;
    for (Element signatureReference : signatureReferences) {
      if (XADES_SIGNED_PROPERTIES.equals(signatureReference.getAttribute("Type")))
        nrOfSignedPropertiesReferences++;
    }
    if (nrOfSignedPropertiesReferences == 1) return null;
    String errorMessage;
    errorMessage = nrOfSignedPropertiesReferences == 0 ?  "Signed properties missing" : "Multiple signed properties";
    logger.info(errorMessage);
    return (new DigiDoc4JException(errorMessage));
  }

  private SimpleReport getSimpleReport(Map<String, SimpleReport> simpleReports, String fromSignatureId) {
    logger.debug("signature id : " + fromSignatureId);
    SimpleReport simpleReport = simpleReports.get(fromSignatureId);
    if (simpleReport != null && simpleReports.size() == 1) {
      return simpleReports.values().iterator().next();
    }
    return simpleReport;
  }

  private SignedDocumentValidator openValidator() throws ContainerWithoutSignaturesException {
    try {
      return ASiCContainerValidator.fromDocument(signedDocument);
    } catch (DSSException e) {
      if (StringUtils.equalsIgnoreCase("This is not an ASiC container. The signature cannot be found!", e.getMessage())) {
        throw new ContainerWithoutSignaturesException();
      }
      logger.error("Error validating container: " + e.getMessage());
      throw new TechnicalException("Error validating container: " + e.getMessage(), e);
    }
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
