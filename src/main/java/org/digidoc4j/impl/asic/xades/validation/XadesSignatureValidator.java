/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.xades.validation;

import static org.apache.commons.lang3.StringUtils.equalsIgnoreCase;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.exceptions.CertificateRevokedException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidOcspNonceException;
import org.digidoc4j.exceptions.InvalidTimestampException;
import org.digidoc4j.exceptions.MultipleSignedPropertiesException;
import org.digidoc4j.exceptions.SignedPropertiesMissingException;
import org.digidoc4j.exceptions.WrongPolicyIdentifierException;
import org.digidoc4j.exceptions.WrongPolicyIdentifierQualifierException;
import org.digidoc4j.impl.asic.OcspNonceValidator;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.xades.XPathQueryHolder;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

/**
 * Signature validator for Xades signatures.
 */
public class XadesSignatureValidator implements SignatureValidator {

  public static final String TM_POLICY = "1.3.6.1.4.1.10015.1000.3.2.1";
  private static final Logger logger = LoggerFactory.getLogger(XadesSignatureValidator.class);
  private static final String OIDAS_URN = "OIDAsURN";
  private static final String XADES_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";
  protected XadesSignature signature;
  private transient Reports validationReport;
  private transient SimpleReport simpleReport;
  private List<DigiDoc4JException> validationErrors = new ArrayList<>();
  private List<DigiDoc4JException> validationWarnings = new ArrayList<>();
  private String signatureId;

  /**
   * Constructor.
   *
   * @param signature Signature object for validation
   */
  public XadesSignatureValidator(XadesSignature signature) {
    this.signature = signature;
    signatureId = signature.getId();
  }

  @Override
  public SignatureValidationResult extractValidationErrors() {
    logger.debug("Extracting validation errors");
    XadesValidationResult validationResult = signature.validate();
    validationReport = validationResult.getReport();
    Map<String, SimpleReport> simpleReports = validationResult.extractSimpleReports();
    simpleReport = getSimpleReport(simpleReports);
    populateValidationErrors();
    return createValidationResult();
  }

  /*
   * RESTRICTED METHODS
   */

  protected void populateValidationErrors() {
    this.addPolicyValidationErrors();
    this.addPolicyUriValidationErrors();
    this.addPolicyErrors();
    this.addSignedPropertiesReferenceValidationErrors();
    this.addReportedErrors();
    this.addReportedWarnings();
    this.addTimestampErrors();
    this.addOcspErrors();
  }

  protected void addValidationError(DigiDoc4JException error) {
    String sigId = getDssSignature().getId();
    error.setSignatureId(sigId);
    validationErrors.add(error);
  }

  protected void addPolicyErrors() {
    // Do nothing here
  }

  protected XAdESSignature getDssSignature() {
    return this.signature.getDssSignature();
  }

  private void addPolicyValidationErrors() {
    logger.debug("Extracting policy validation errors");
    SignaturePolicy policy = getDssSignature().getPolicyId();
    if (policy != null) {
      String policyIdentifier = Helper.getIdentifier(policy.getIdentifier());
      if (!StringUtils.equals(TM_POLICY, policyIdentifier)) {
        addValidationError(new WrongPolicyIdentifierException("Wrong policy identifier: " + policyIdentifier));
      } else {
        addPolicyIdentifierQualifierValidationErrors();
      }
    }
  }

  private void addPolicyUriValidationErrors() {
    logger.debug("Extracting policy URL validation errors");
    SignaturePolicy policy = getDssSignature().getPolicyId();
    if (policy != null) {
      if (StringUtils.isBlank(policy.getUrl())) {
        addValidationError(
            new WrongPolicyIdentifierException("Error: The URL in signature policy is empty or not available"));
      }
    }
  }

  private void addPolicyIdentifierQualifierValidationErrors() {
    logger.debug("Extracting policy identifier qualifier validation errors");
    XPathQueryHolder xPathQueryHolder = getDssSignature().getXPathQueryHolder();
    Element signatureElement = getDssSignature().getSignatureElement();
    Element element = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER);
    Element identifier = DomUtils.getElement(element, "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier");
    String qualifier = identifier.getAttribute("Qualifier");
    if (!StringUtils.equals(OIDAS_URN, qualifier)) {
      addValidationError(
          new WrongPolicyIdentifierQualifierException("Wrong policy identifier qualifier: " + qualifier));
    }
  }

  private void addSignedPropertiesReferenceValidationErrors() {
    logger.debug("Extracting signed properties reference validation errors");
    int propertiesReferencesCount = findSignedPropertiesReferencesCount();
    String sigId = getDssSignature().getId();
    if (propertiesReferencesCount == 0) {
      logger.error("Signed properties are missing for signature " + sigId);
      addValidationError(new SignedPropertiesMissingException("Signed properties missing"));
    }
    if (propertiesReferencesCount > 1) {
      logger.error("Multiple signed properties for signature " + sigId);
      DigiDoc4JException error = new MultipleSignedPropertiesException("Multiple signed properties");
      addValidationError(error);
    }
  }

  private int findSignedPropertiesReferencesCount() {
    List<Element> signatureReferences = getDssSignature().getSignatureReferences();
    int nrOfSignedPropertiesReferences = 0;
    for (Element signatureReference : signatureReferences) {
      String type = signatureReference.getAttribute("Type");
      if (StringUtils.equals(XADES_SIGNED_PROPERTIES, type))
        nrOfSignedPropertiesReferences++;
    }
    return nrOfSignedPropertiesReferences;
  }

  private void addReportedErrors() {
    logger.debug("Extracting reported errors");
    if (simpleReport != null) {
      for (String errorMessage : simpleReport.getErrors(signatureId)) {
        if (isRedundantErrorMessage(errorMessage)) {
          logger.debug("Ignoring redundant error message: " + errorMessage);
          continue;
        }
        logger.error(errorMessage);
        if (errorMessage.contains(MessageTag.BBB_XCV_ISCR_ANS.getMessage())) {
          addValidationError(new CertificateRevokedException(errorMessage));
        } else if (errorMessage.contains(MessageTag.PSV_IPSVC_ANS.getMessage())) {
          addValidationError(new CertificateRevokedException(errorMessage));
        } else {
          String sigId = getDssSignature().getId();
          addValidationError(new DigiDoc4JException(errorMessage, sigId));
        }
      }
    }
  }

  private boolean isRedundantErrorMessage(String errorMessage) {
    return equalsIgnoreCase(errorMessage, MessageTag.ADEST_ROBVPIIC_ANS.getMessage())
        || equalsIgnoreCase(errorMessage, MessageTag.LTV_ABSV_ANS.getMessage())
        || equalsIgnoreCase(errorMessage, MessageTag.ARCH_LTVV_ANS.getMessage())
        || equalsIgnoreCase(errorMessage, MessageTag.BBB_XCV_RFC_ANS.getMessage())
        || equalsIgnoreCase(errorMessage, MessageTag.BBB_XCV_SUB_ANS.getMessage());
  }

  private void addReportedWarnings() {
    if (simpleReport != null) {
      for (String warning : simpleReport.getWarnings(signatureId)) {
        logger.warn(warning);
        validationWarnings.add(new DigiDoc4JException(warning, signatureId));
      }
    }
  }

  private void addTimestampErrors() {
    if (!isTimestampValidForSignature()) {
      logger.error("Signature " + signatureId + " has an invalid timestamp");
      addValidationError(new InvalidTimestampException());
    }
  }

  private boolean isTimestampValidForSignature() {
    logger.debug("Finding timestamp errors for signature " + signatureId);
    DiagnosticData diagnosticData = validationReport.getDiagnosticData();
    if (diagnosticData == null) {
      return true;
    }
    List<String> timestampIdList = diagnosticData.getTimestampIdList(signatureId);
    if (timestampIdList == null || timestampIdList.isEmpty()) {
      return true;
    }
    String timestampId = timestampIdList.get(0);
    DetailedReport detailedReport = validationReport.getDetailedReport();
    Indication indication = detailedReport.getTimestampValidationIndication(timestampId);
    return isIndicationValid(indication);
  }

  private SimpleReport getSimpleReport(Map<String, SimpleReport> simpleReports) {
    SimpleReport simpleRep = simpleReports.get(signatureId);
    if (simpleRep != null && simpleReports.size() == 1) {
      return simpleReports.values().iterator().next();
    }
    return simpleRep;
  }

  private void addOcspErrors() {
    OcspNonceValidator ocspValidator = new OcspNonceValidator(getDssSignature());
    if (!ocspValidator.isValid()) {
      logger.error("OCSP nonce is invalid");
      addValidationError(new InvalidOcspNonceException());
    }
  }

  private SignatureValidationResult createValidationResult() {
    SignatureValidationResult result = new SignatureValidationResult();
    result.setErrors(validationErrors);
    result.setWarnings(validationWarnings);
    return result;
  }

  private boolean isIndicationValid(Indication indication) {
    return indication == Indication.PASSED || indication == Indication.TOTAL_PASSED;
  }

}
