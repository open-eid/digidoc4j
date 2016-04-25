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

import static org.apache.commons.lang.StringUtils.isBlank;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.exceptions.CertificateRevokedException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidOcspNonceException;
import org.digidoc4j.exceptions.InvalidTimestampException;
import org.digidoc4j.exceptions.MiltipleSignedPropertiesException;
import org.digidoc4j.exceptions.PolicyUrlMissingException;
import org.digidoc4j.exceptions.SignedPropertiesMissingException;
import org.digidoc4j.exceptions.WrongPolicyIdentifierException;
import org.digidoc4j.exceptions.WrongPolicyIdentifierQualifierException;
import org.digidoc4j.impl.bdoc.OcspNonceValidator;
import org.digidoc4j.impl.bdoc.xades.validation.XadesValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.Conclusion;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class XadesSignatureValidator implements Serializable {

  private final static Logger logger = LoggerFactory.getLogger(XadesSignatureValidator.class);
  public static final String TM_POLICY = "urn:oid:1.3.6.1.4.1.10015.1000.3.2.1";
  private static final String OIDAS_URN = "OIDAsURN";
  private static final String XADES_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";
  private transient Reports validationReport;
  private transient SimpleReport simpleReport;
  private List<DigiDoc4JException> validationErrors = new ArrayList<>();
  private List<DigiDoc4JException> validationWarnings = new ArrayList<>();
  private String signatureId;
  private XadesSignature signature;

  public XadesSignatureValidator(XadesSignature signature) {
    this.signature = signature;
    signatureId = signature.getId();
  }

  public SignatureValidationResult extractValidationErrors() {
    logger.debug("Extracting validation errors");
    XadesValidationResult validationResult = signature.validate();
    validationReport = validationResult.getReport();
    Map<String, SimpleReport> simpleReports = validationResult.extractSimpleReports();
    simpleReport = getSimpleReport(simpleReports);
    populateValidationErrors();
    return createValidationResult();
  }

  public Reports getDssValidationReport() {
    if(validationReport == null) {
      validationReport = signature.validate().getReport();
    }
    return validationReport;
  }

  protected void populateValidationErrors() {
    addPolicyValidationErrors();
    addSignedPropertiesReferenceValidationErrors();
    addReportedErrors();
    addReportedWarnings();
    addTimestampErrors();
    addOcspNonceErrors();
  }

  private void addPolicyValidationErrors() {
    logger.debug("Extracting policy validation errors");
    SignaturePolicy policy = getDssSignature().getPolicyId();
    if(policy != null) {
      String policyIdentifier = policy.getIdentifier().trim();
      if (!StringUtils.equals(TM_POLICY, policyIdentifier)) {
        addValidationError(new WrongPolicyIdentifierException("Wrong policy identifier: " + policyIdentifier));
      } else {
        if (isBlank(policy.getUrl())) {
          addValidationError(new PolicyUrlMissingException("Policy url is missing for identifier: " + policyIdentifier));
        }
        addPolicyIdentifierQualifierValidationErrors();
      }
    }
  }

  private void addPolicyIdentifierQualifierValidationErrors() {
    logger.debug("Extracting policy identifier qualifier validation errors");
    XPathQueryHolder xPathQueryHolder = getDssSignature().getXPathQueryHolder();
    Element signatureElement = getDssSignature().getSignatureElement();
    Element element = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER);
    Element identifier = DSSXMLUtils.getElement(element, "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier");
    String qualifier = identifier.getAttribute("Qualifier");
    if (!StringUtils.equals(OIDAS_URN, qualifier)) {
      addValidationError(new WrongPolicyIdentifierQualifierException("Wrong policy identifier qualifier: " + qualifier));
    }
  }

  private void addSignedPropertiesReferenceValidationErrors() {
    logger.debug("Extracting signed properties reference validation errors");
    int propertiesReferencesCount = findSignedPropertiesReferencesCount();
    String signatureId = getDssSignature().getId();
    if(propertiesReferencesCount == 0) {
      logger.error("Signed properties are missing for signature " + signatureId);
      addValidationError(new SignedPropertiesMissingException("Signed properties missing"));
    }
    if (propertiesReferencesCount > 1) {
      logger.error("Multiple signed properties for signature " + signatureId);
      DigiDoc4JException error = new MiltipleSignedPropertiesException("Multiple signed properties");
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
      for (Conclusion.BasicInfo error : simpleReport.getErrors(signatureId)) {
        String errorMessage = error.toString();
        logger.error(errorMessage);
        if(errorMessage.contains(MessageTag.BBB_XCV_ISCR_ANS.getMessage()))
          addValidationError(new CertificateRevokedException(error.toString()));
        else
          addValidationError(new DigiDoc4JException(error.toString()));
      }
    }
  }

  private void addReportedWarnings() {
    if (simpleReport != null) {
      for (Conclusion.BasicInfo warning : simpleReport.getWarnings(signatureId)) {
        String message = warning.toString();
        logger.warn(message);
        validationWarnings.add(new DigiDoc4JException(warning.toString()));
      }
    }
  }

  private void addTimestampErrors() {
    if(!isTimestampValidForSignature()) {
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
    if(timestampIdList == null || timestampIdList.isEmpty()) {
      return true;
    }
    String timestampId = timestampIdList.get(0);
    return diagnosticData.isTimestampMessageImprintIntact(timestampId) && !isIndeterminateTimestamp();
  }

  private boolean isIndeterminateTimestamp() {
    String indication = simpleReport.getIndication(signatureId);
    String subIndication = simpleReport.getSubIndication(signatureId);
    if (Indication.INDETERMINATE.equals(indication)) {
      return SubIndication.NO_VALID_TIMESTAMP.equals(subIndication);
    }
    return false;
  }

  private SimpleReport getSimpleReport(Map<String, SimpleReport> simpleReports) {
    SimpleReport simpleReport = simpleReports.get(signatureId);
    if (simpleReport != null && simpleReports.size() == 1) {
      return simpleReports.values().iterator().next();
    }
    return simpleReport;
  }

  private void addOcspNonceErrors() {
    if(!new OcspNonceValidator(getDssSignature()).isValid()) {
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

  protected void addValidationError(DigiDoc4JException error) {
    validationErrors.add(error);
  }

  private XAdESSignature getDssSignature() {
    return signature.getDssSignature();
  }
}
