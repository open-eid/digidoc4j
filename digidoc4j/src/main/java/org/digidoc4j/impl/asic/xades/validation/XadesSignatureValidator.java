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
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.*;
import org.digidoc4j.impl.SimpleValidationResult;
import org.digidoc4j.impl.asic.OcspNonceValidator;
import org.digidoc4j.impl.asic.OcspResponderValidator;
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

  private static final Logger logger = LoggerFactory.getLogger(XadesSignatureValidator.class);
  public static final String TM_POLICY = "1.3.6.1.4.1.10015.1000.3.2.1";
  private static final String OIDAS_URN = "OIDAsURN";
  private static final String XADES_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";
  protected XadesSignature signature;
  private transient Reports validationReport;
  private transient SimpleReport simpleReport;
  private List<DigiDoc4JException> validationErrors = new ArrayList<>();
  private List<DigiDoc4JException> validationWarnings = new ArrayList<>();
  private String signatureId;
  protected Configuration configuration;

  /**
   * Constructor.
   *
   * @param signature Signature object for validation
   * @param configuration configuretion
   */
  public XadesSignatureValidator(XadesSignature signature, Configuration configuration) {
    this.signature = signature;
    this.signatureId = signature.getId();
    this.configuration = configuration;
  }

  @Override
  public ValidationResult extractResult() {
    logger.debug("Extracting validation errors");
    XadesValidationResult validationResult = this.signature.validate();
    this.validationReport = validationResult.getReports();
    this.simpleReport = this.getSimpleReport(validationResult.buildSimpleReports());
    this.populateValidationErrors();
    if (configuration.isFullReportNeeded()){
      FullSimpleReportBuilder detailedReportParser = new FullSimpleReportBuilder(validationReport.getDetailedReport());
      detailedReportParser.addDetailedReportEexeptions(validationErrors, validationWarnings);
    }
    return this.createValidationResult();
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
    this.addOCSPErrors();
  }

  protected void addValidationError(DigiDoc4JException error) {
    error.setSignatureId(this.getDssSignature().getId());
    this.validationErrors.add(error);
  }

  protected void addValidationWarning(DigiDoc4JException warning) {
    warning.setSignatureId(this.getDssSignature().getId());
    this.validationWarnings.add(warning);
  }

  protected void addPolicyErrors() {
    // Do nothing here
  }

  protected boolean isSignaturePolicyImpliedElementPresented() {
    XPathQueryHolder xPathQueryHolder = this.getDssSignature().getXPathQueryHolder();
    Element signaturePolicyImpliedElement = DomUtils.getElement(this.getDssSignature().getSignatureElement(),
        String.format("%s%s", xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER,
            xPathQueryHolder.XPATH__SIGNATURE_POLICY_IMPLIED.replace(".", "")));
    return signaturePolicyImpliedElement != null;
  }

  protected XAdESSignature getDssSignature() {
    return this.signature.getDssSignature();
  }

  private void addPolicyValidationErrors() {
    logger.debug("Extracting policy validation errors");
    XAdESSignature dssSignature = this.getDssSignature();
    SignaturePolicy policy = dssSignature.getPolicyId();
    if (policy != null && dssSignature.getSignatureTimestamps().isEmpty()) {
      String policyIdentifier = Helper.getIdentifier(policy.getIdentifier());
      if (!StringUtils.equals(XadesSignatureValidator.TM_POLICY, policyIdentifier)) {
        this.addValidationError(new WrongPolicyIdentifierException(String.format("Wrong policy identifier: %s", policyIdentifier)));
      } else {
        this.addPolicyIdentifierQualifierValidationErrors();
      }
    } else if (policy != null && !dssSignature.getSignatureTimestamps().isEmpty()) {
      logger.debug("Signature profile is not LT_TM, but has defined policy");
    }
  }

  private void addPolicyUriValidationErrors() {
    logger.debug("Extracting policy URL validation errors");
    SignaturePolicy policy = this.getDssSignature().getPolicyId();
    if (policy != null && !isSignaturePolicyImpliedElementPresented()) {
      if (StringUtils.isBlank(policy.getUrl())) {
        this.addValidationError(new WrongPolicyIdentifierException("Error: The URL in signature policy is empty or not available"));
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
    if (!StringUtils.equals(XadesSignatureValidator.OIDAS_URN, qualifier)) {
      this.addValidationError(new WrongPolicyIdentifierQualifierException(String.format("Wrong policy identifier qualifier: %s", qualifier)));
    }
  }

  private void addSignedPropertiesReferenceValidationErrors() {
    logger.debug("Extracting signed properties reference validation errors");
    int propertiesReferencesCount = this.findSignedPropertiesReferencesCount();
    if (propertiesReferencesCount == 0) {
      this.addValidationError(new SignedPropertiesMissingException(String.format("SignedProperties Reference element is missing")));
    }
    if (propertiesReferencesCount > 1) {
      this.addValidationError(new MultipleSignedPropertiesException(String.format("Multiple signed properties")));
    }
  }

  private int findSignedPropertiesReferencesCount() {
    List<Element> signatureReferences = this.getDssSignature().getSignatureReferences();
    int nrOfSignedPropertiesReferences = 0;
    for (Element signatureReference : signatureReferences) {
      String type = signatureReference.getAttribute("Type");
      if (StringUtils.equals(XadesSignatureValidator.XADES_SIGNED_PROPERTIES, type))
        nrOfSignedPropertiesReferences++;
    }
    return nrOfSignedPropertiesReferences;
  }

  private void addReportedErrors() {
    logger.debug("Extracting reported errors");
    if (this.simpleReport != null) {
      for (String errorMessage : this.simpleReport.getErrors(this.signatureId)) {
        if (this.isRedundantErrorMessage(errorMessage)) {
          logger.debug("Ignoring redundant error message: " + errorMessage);
          continue;
        }
        if (errorMessage.contains(MessageTag.BBB_XCV_ISCR_ANS.getMessage())) {
          this.addValidationError(new CertificateRevokedException(errorMessage));
        } else if (errorMessage.contains(MessageTag.PSV_IPSVC_ANS.getMessage())) {
          this.addValidationError(new CertificateRevokedException(errorMessage));
        } else {
          this.addValidationError(new DigiDoc4JException(errorMessage, this.getDssSignature().getId()));
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
    if (this.simpleReport != null) {
      for (String warning : this.simpleReport.getWarnings(this.signatureId)) {
        this.validationWarnings.add(new DigiDoc4JException(warning, this.signatureId));
      }
    }
  }

  private void addTimestampErrors() {
    if (!isTimestampValidForSignature()) {
      this.addValidationError(new InvalidTimestampException());
    }
  }

  private boolean isTimestampValidForSignature() {
    logger.debug("Finding timestamp errors for signature " + signatureId);
    DiagnosticData diagnosticData = this.validationReport.getDiagnosticData();
    if (diagnosticData == null) {
      return true;
    }
    List<String> timestampIdList = diagnosticData.getTimestampIdList(signatureId);
    if (CollectionUtils.isEmpty(timestampIdList)) {
      return true;
    }
    String timestampId = timestampIdList.get(0);
    DetailedReport detailedReport = this.validationReport.getDetailedReport();
    return this.isIndicationValid(detailedReport.getTimestampValidationIndication(timestampId));
  }

  private SimpleReport getSimpleReport(Map<String, SimpleReport> simpleReports) {
    SimpleReport simpleRep = simpleReports.get(this.signatureId);
    if (simpleRep != null && simpleReports.size() == 1) {
      return simpleReports.values().iterator().next();
    }
    return simpleRep;
  }

  private void addOCSPErrors() {
    OcspNonceValidator ocspValidator = new OcspNonceValidator(getDssSignature());
    if (!ocspValidator.isValid()) {
      this.addValidationError(new InvalidOcspNonceException());
    }
    OcspResponderValidator ocspResponderOidValidator = new OcspResponderValidator(this.signature, this.configuration);
    if (!ocspResponderOidValidator.isValid()) {
      this.addValidationError(new InvalidOcspResponderException());
    }
  }

  private ValidationResult createValidationResult() {
    SimpleValidationResult result = new SimpleValidationResult("XAdES signature");
    result.setErrors(this.validationErrors);
    result.setWarnings(this.validationWarnings);
    return result;
  }

  private boolean isIndicationValid(Indication indication) {
    return Arrays.asList(Indication.PASSED, Indication.TOTAL_PASSED).contains(indication);
  }

}
