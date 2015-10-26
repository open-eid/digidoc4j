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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.exceptions.CertificateRevokedException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidTimestampException;
import org.digidoc4j.exceptions.MiltipleSignedPropertiesException;
import org.digidoc4j.exceptions.PolicyUrlMissingException;
import org.digidoc4j.exceptions.SignedPropertiesMissingException;
import org.digidoc4j.exceptions.WrongPolicyIdentifierException;
import org.digidoc4j.exceptions.WrongPolicyIdentifierQualifierException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.signature.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignaturePolicy;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.rules.MessageTag;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

public class XadesSignatureValidator {

  private final static Logger logger = LoggerFactory.getLogger(XadesSignatureValidator.class);
  private static final String TM_POLICY = "urn:oid:1.3.6.1.4.1.10015.1000.3.2.1";
  private static final String OIDAS_URN = "OIDAsURN";
  private static final String XADES_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";
  private Reports validationReport;
  private Map<String, SimpleReport> simpleReports;

  public XadesSignatureValidator(Reports validationReport) {
    this.validationReport = validationReport;
    this.simpleReports = extractSimpleReports(validationReport);
  }

  public List<DigiDoc4JException> extractErrors(XAdESSignature advancedSignature) {
    List<DigiDoc4JException> validationErrors = new ArrayList<>();
    String signatureId = advancedSignature.getId();
    logger.debug("Extracting errors for signature " + signatureId);
    addPolicyValidationErrors(validationErrors, advancedSignature);
    addSignedPropertiesReferenceValidationErrors(validationErrors, advancedSignature);
    addReportedErrors(validationErrors, signatureId);
    addTimestampErrors(validationErrors, signatureId);
    return validationErrors;
  }

  private void addPolicyValidationErrors(List<DigiDoc4JException> validationErrors, AdvancedSignature advancedSignature) {
    logger.debug("Extracting policy validation errors");
    SignaturePolicy policy = advancedSignature.getPolicyId();
    if(policy != null) {
      String policyIdentifier = policy.getIdentifier().trim();
      if (!StringUtils.equals(TM_POLICY, policyIdentifier)) {
        validationErrors.add(new WrongPolicyIdentifierException("Wrong policy identifier: " + policyIdentifier));
      } else {
        if (isBlank(policy.getUrl())) {
          validationErrors.add(new PolicyUrlMissingException("Policy url is missing for identifier: " + policyIdentifier));
        }
        addPolicyIdentifierQualifierValidationErrors(validationErrors, (XAdESSignature) advancedSignature);
      }
    }
  }

  private void addPolicyIdentifierQualifierValidationErrors(List<DigiDoc4JException> validationErrors, XAdESSignature advancedSignature) {
    logger.debug("Extracting policy identifier qualifier validation errors");
    XPathQueryHolder xPathQueryHolder = advancedSignature.getXPathQueryHolder();
    Element signatureElement = advancedSignature.getSignatureElement();
    Element element = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER);
    Element identifier = DSSXMLUtils.getElement(element, "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier");
    String qualifier = identifier.getAttribute("Qualifier");
    if (!StringUtils.equals(OIDAS_URN, qualifier)) {
      validationErrors.add(new WrongPolicyIdentifierQualifierException("Wrong policy identifier qualifier: " + qualifier));
    }
  }

  private void addSignedPropertiesReferenceValidationErrors(List<DigiDoc4JException> validationErrors, AdvancedSignature advancedSignature) {
    logger.debug("Extracting signed properties reference validation errors");
    int propertiesReferencesCount = findSignedPropertiesReferencesCount((XAdESSignature) advancedSignature);
    String signatureId = advancedSignature.getId();
    if(propertiesReferencesCount == 0) {
      logger.error("Signed properties are missing for signature " + signatureId);
      validationErrors.add(new SignedPropertiesMissingException("Signed properties missing"));
    }
    if (propertiesReferencesCount > 1) {
      logger.error("Multiple signed properties for signature " + signatureId);
      validationErrors.add(new MiltipleSignedPropertiesException("Multiple signed properties"));
    }
  }

  private int findSignedPropertiesReferencesCount(XAdESSignature advancedSignature) {
    List<Element> signatureReferences = advancedSignature.getSignatureReferences();
    int nrOfSignedPropertiesReferences = 0;
    for (Element signatureReference : signatureReferences) {
      String type = signatureReference.getAttribute("Type");
      if (StringUtils.equals(XADES_SIGNED_PROPERTIES, type))
        nrOfSignedPropertiesReferences++;
    }
    return nrOfSignedPropertiesReferences;
  }

  private void addReportedErrors(List<DigiDoc4JException> validationErrors, String reportSignatureId) {
    logger.debug("Extracting reported errors");
    SimpleReport simpleReport = getSimpleReport(reportSignatureId);
    if (simpleReport != null) {
      for (Conclusion.BasicInfo error : simpleReport.getErrors(reportSignatureId)) {
        String errorMessage = error.toString();
        logger.error(errorMessage);
        if(errorMessage.contains(MessageTag.BBB_XCV_ISCR_ANS.getMessage()))
          validationErrors.add(new CertificateRevokedException(error.toString()));
        else
          validationErrors.add(new DigiDoc4JException(error.toString()));
      }
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

  private Map<String, SimpleReport> extractSimpleReports(Reports report) {
    Map<String, SimpleReport> simpleReports = new LinkedHashMap<>();
    do {
      SimpleReport simpleReport = report.getSimpleReport();
      if (simpleReport.getSignatureIdList().size() > 0) {
        simpleReports.put(simpleReport.getSignatureIdList().get(0), simpleReport);
      }
      report = report.getNextReports();
    } while (report != null);
    return simpleReports;
  }

  private SimpleReport getSimpleReport(String fromSignatureId) {
    SimpleReport simpleReport = simpleReports.get(fromSignatureId);
    if (simpleReport != null && simpleReports.size() == 1) {
      return simpleReports.values().iterator().next();
    }
    return simpleReport;
  }

}
