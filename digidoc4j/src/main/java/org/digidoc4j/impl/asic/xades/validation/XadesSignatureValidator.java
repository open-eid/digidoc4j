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

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xades.definition.XAdESPath;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.CertificateRevokedException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidOcspNonceException;
import org.digidoc4j.exceptions.InvalidOcspResponderException;
import org.digidoc4j.exceptions.InvalidTimestampException;
import org.digidoc4j.exceptions.MultipleSignedPropertiesException;
import org.digidoc4j.exceptions.SignedPropertiesMissingException;
import org.digidoc4j.exceptions.WrongPolicyIdentifierException;
import org.digidoc4j.exceptions.WrongPolicyIdentifierQualifierException;
import org.digidoc4j.impl.SimpleValidationResult;
import org.digidoc4j.impl.asic.OcspNonceValidator;
import org.digidoc4j.impl.asic.OcspResponderValidator;
import org.digidoc4j.impl.asic.TmSignaturePolicyType;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Signature validator for Xades signatures.
 */
public class XadesSignatureValidator implements SignatureValidator {

  private static final Logger LOGGER = LoggerFactory.getLogger(XadesSignatureValidator.class);
  private static final String XADES_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";
  protected final XadesSignature signature;
  private transient Reports validationReport;
  private transient SimpleReport simpleReport;
  private final List<DigiDoc4JException> validationErrors = new ArrayList<>();
  private final List<DigiDoc4JException> validationWarnings = new ArrayList<>();
  private final String signatureId;
  private final String signatureUniqueId;
  protected final Configuration configuration;

  /**
   * Constructor.
   *
   * @param signature     Signature object for validation
   * @param configuration configuration
   */
  public XadesSignatureValidator(XadesSignature signature, Configuration configuration) {
    this.signature = signature;
    this.signatureId = signature.getId();
    this.signatureUniqueId = signature.getUniqueId();
    this.configuration = configuration;
  }

  @Override
  public ValidationResult extractResult() {
    LOGGER.debug("Extracting validation errors");
    XadesValidationResult validationResult = this.signature.validate();
    this.validationReport = validationResult.getReports();
    this.simpleReport = this.getSimpleReport(validationResult.buildSimpleReports());
    this.populateValidationErrors();
    if (configuration.isFullReportNeeded()) {
      FullSimpleReportBuilder detailedReportParser = new FullSimpleReportBuilder(validationReport.getDetailedReport());
      detailedReportParser.addDetailedReportExceptions(validationErrors, validationWarnings);
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
    error.setSignatureId(this.signatureId);
    this.validationErrors.add(error);
  }

  protected void addValidationWarning(DigiDoc4JException warning) {
    warning.setSignatureId(this.signatureId);
    this.validationWarnings.add(warning);
  }

  protected void addPolicyErrors() {
    // Do nothing here
  }

  protected boolean isSignaturePolicyImpliedElementPresented() {
    XAdESPath xAdESPaths = this.getDssSignature().getXAdESPaths();
    Element signaturePolicyImpliedElement = DomUtils.getElement(this.getDssSignature().getSignatureElement(),
            String.format("%s%s", xAdESPaths.getSignaturePolicyIdentifierPath(),
                    xAdESPaths.getCurrentSignaturePolicyImplied().replace(".", "")));
    return signaturePolicyImpliedElement != null;
  }

  protected XAdESSignature getDssSignature() {
    return this.signature.getDssSignature();
  }

  private void addPolicyValidationErrors() {
    LOGGER.debug("Extracting policy validation errors");
    XAdESSignature dssSignature = this.getDssSignature();
    SignaturePolicy policy = dssSignature.getSignaturePolicy();
    if (policy == null) {
      return;
    }
    addPolicyImpliedWarning();
    if (dssSignature.getSignatureTimestamps().isEmpty()) {
      String policyIdentifier = Helper.getIdentifier(policy.getIdentifier());
      if (!StringUtils.equals(TmSignaturePolicyType.BDOC_2_1_0.getOid(), policyIdentifier)) {
        this.addValidationError(new WrongPolicyIdentifierException(String.format("Wrong policy identifier: %s", policyIdentifier)));
      } else {
        this.addPolicyIdentifierQualifierValidationErrors();
      }
    } else if (!dssSignature.getSignatureTimestamps().isEmpty()) {
      LOGGER.debug("Signature profile is not LT_TM, but has defined policy");
    }
  }

  private void addPolicyImpliedWarning() {
    if (isSignaturePolicyImpliedElementPresented()) {
      this.addValidationWarning(new WrongPolicyIdentifierException("Signature created with implied policy, additional conditions may apply!"));
    }
  }

  private void addPolicyUriValidationErrors() {
    LOGGER.debug("Extracting policy URL validation errors");
    SignaturePolicy policy = this.getDssSignature().getSignaturePolicy();
    if (policy != null && !isSignaturePolicyImpliedElementPresented()) {
      String policyIdentifier = Helper.getIdentifier(policy.getIdentifier());
      if (TmSignaturePolicyType.isTmPolicyOid(policyIdentifier)) {
        String policyUrl = policy.getUri();
        if (StringUtils.equals(policyIdentifier, policyUrl)) {
          // DD4J-730: Starting from DSS version 5.8, the policy URL defaults to the policy identifier OID if the URL is
          //  missing in the signature. Since the BDOC standard requires that the URL is always present, this workaround
          //  is required to identify cases when the URL is missing.
          // TODO: review the usefulness and correctness of this workaround as soon as DSS is updated!
          policyUrl = null;
        }
        if (StringUtils.isBlank(policyUrl)) {
          this.addValidationError(new WrongPolicyIdentifierException("Error: The URL in signature policy is empty or not available"));
        }
      }
    }
  }

  private void addPolicyIdentifierQualifierValidationErrors() {
    LOGGER.debug("Extracting policy identifier qualifier validation errors");
    XAdESPath xAdESPaths = getDssSignature().getXAdESPaths();
    Element signatureElement = getDssSignature().getSignatureElement();
    String xAdESPrefix = xAdESPaths.getNamespace().getPrefix();
    Element element = DomUtils.getElement(signatureElement, xAdESPaths.getSignaturePolicyIdentifierPath());
    Element identifier = DomUtils.getElement(element, "./" + xAdESPrefix + ":SignaturePolicyId/" + xAdESPrefix
            + ":SigPolicyId/" + xAdESPrefix + ":Identifier");
    String qualifier = identifier.getAttribute("Qualifier");
    if (!StringUtils.equals(ObjectIdentifierQualifier.OID_AS_URN.getValue(), qualifier)) {
      this.addValidationError(new WrongPolicyIdentifierQualifierException(String.format("Wrong policy identifier qualifier: %s", qualifier)));
    }
  }

  private void addSignedPropertiesReferenceValidationErrors() {
    LOGGER.debug("Extracting signed properties reference validation errors");
    int propertiesReferencesCount = this.findSignedPropertiesReferencesCount();
    if (propertiesReferencesCount == 0) {
      this.addValidationError(new SignedPropertiesMissingException("SignedProperties Reference element is missing"));
    }
    if (propertiesReferencesCount > 1) {
      this.addValidationError(new MultipleSignedPropertiesException("Multiple signed properties"));
    }
  }

  private int findSignedPropertiesReferencesCount() {
    return (int) this
            .getDssSignature()
            .getReferences()
            .stream()
            .filter(r -> StringUtils.equals(XadesSignatureValidator.XADES_SIGNED_PROPERTIES, r.getType()))
            .count();
  }

  private void addReportedErrors() {
    LOGGER.debug("Extracting reported errors");
    if (this.simpleReport != null) {
      I18nProvider i18nProvider = new I18nProvider();
      Stream.concat(
              Stream.concat(
                      this.simpleReport.getAdESValidationErrors(this.signatureUniqueId).stream(),
                      this.simpleReport.getQualificationErrors(this.signatureUniqueId).stream()
              ).map(Message::getValue),
              this.simpleReport.getSignatureTimestamps(this.signatureUniqueId).stream()
                      .flatMap(timestamp -> getTokenMessages(timestamp, details -> details.getError().stream()))
                      .map(XmlMessage::getValue)
      ).distinct().forEach(errorMessage -> {
        if (errorMessage.contains(i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS))) {
          this.addValidationError(new CertificateRevokedException(errorMessage));
        } else if (errorMessage.contains(i18nProvider.getMessage(MessageTag.PSV_IPSVC_ANS))) {
          this.addValidationError(new CertificateRevokedException(errorMessage));
        } else {
          this.addValidationError(new DigiDoc4JException(errorMessage, this.signatureId));
        }
      });
    }
  }

  private void addReportedWarnings() {
    if (this.simpleReport != null) {
      Stream.concat(
              Stream.concat(
                      this.simpleReport.getAdESValidationWarnings(this.signatureUniqueId).stream(),
                      this.simpleReport.getQualificationWarnings(this.signatureUniqueId).stream()
              ).map(Message::getValue),
              this.simpleReport.getSignatureTimestamps(this.signatureUniqueId).stream()
                      .flatMap(timestamp -> getTokenMessages(timestamp, details -> details.getWarning().stream()))
                      .map(XmlMessage::getValue)
      ).distinct().forEach(warningMessage -> {
        this.addValidationWarning(new DigiDoc4JException(warningMessage, this.signatureId));
      });
    }
  }

  private void addTimestampErrors() {
    if (!isTimestampValidForSignature()) {
      this.addValidationError(new InvalidTimestampException());
    }
  }

  private boolean isTimestampValidForSignature() {
    LOGGER.debug("Finding timestamp errors for signature " + signatureId);
    DiagnosticData diagnosticData = this.validationReport.getDiagnosticData();
    if (diagnosticData == null) {
      return true;
    }
    List<String> timestampIdList = diagnosticData.getTimestampIdList(signatureUniqueId);
    if (CollectionUtils.isEmpty(timestampIdList)) {
      return true;
    }
    String timestampId = timestampIdList.get(0);
    DetailedReport detailedReport = this.validationReport.getDetailedReport();
    return this.isIndicationValid(detailedReport.getBasicTimestampValidationIndication(timestampId));
  }

  private SimpleReport getSimpleReport(Map<String, SimpleReport> simpleReports) {
    SimpleReport simpleRep = simpleReports.get(this.signatureUniqueId);
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

  private static Stream<XmlMessage> getTokenMessages(XmlToken token, Function<XmlDetails, Stream<XmlMessage>> messageExtractor) {
    return (token != null) ? Stream.concat(
            Optional.ofNullable(token.getAdESValidationDetails()).map(messageExtractor).orElseGet(Stream::empty),
            Optional.ofNullable(token.getQualificationDetails()).map(messageExtractor).orElseGet(Stream::empty)
    ) : Stream.empty();
  }

}
