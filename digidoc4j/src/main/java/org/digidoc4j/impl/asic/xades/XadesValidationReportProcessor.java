package org.digidoc4j.impl.asic.xades;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import eu.europa.esig.dss.validation.reports.Reports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class XadesValidationReportProcessor {

  private static final Logger LOGGER = LoggerFactory.getLogger(XadesValidationReportProcessor.class);
  private static final I18nProvider i18nProvider = new I18nProvider();
  private static final List<String> WARNING_MESSAGES_TO_IGNORE = Arrays.asList(
          i18nProvider.getMessage(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),      // DD4J - 404
          i18nProvider.getMessage(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)      // DD4J - 404
  );
  // DD4J-349: Signature levels that meet the minimal required level
  private static final List<SignatureQualification> SIGNATURE_QUALIFICATIONS_OK = Arrays.asList(
          SignatureQualification.ADESEAL_QC,
          SignatureQualification.QES,
          SignatureQualification.QESIG,
          SignatureQualification.QESEAL
  );
  // DD4J-349: Signature levels that should add a warning into validation reports
  private static final List<SignatureQualification> SIGNATURE_QUALIFICATIONS_WARN = Arrays.asList(
          SignatureQualification.ADESIG_QC
  );
  private static final String SIGNATURE_LEVEL_WARNING = "The signature is not in the Qualified Electronic Signature level!";
  private static final String SIGNATURE_LEVEL_ERROR = "The signature/seal level does not meet the minimal required level!";

  public static void process(Reports validationReports) {
    removeFalsePositiveWarningsFromValidationReports(validationReports);
    ensureMinimalRequiredSignatureLevelsAreMet(validationReports);
  }

  /**
   * DD4J-404
   * Removing warning messages from DSS reports that are considered false-positive by DDJ4 or
   * uncorrectable at the given time.
   * TODO: Not recommended to add anything new here and should be removed at some point
   *
   * @param validationReports
   */
  private static void removeFalsePositiveWarningsFromValidationReports(Reports validationReports) {
    for (XmlToken xmlToken : validationReports.getSimpleReportJaxb().getSignatureOrTimestamp()) {
      if (xmlToken instanceof XmlSignature) {
        removeFalsePositiveWarningsFromSignatureResult((XmlSignature) xmlToken);
      }
    }
  }

  private static void removeFalsePositiveWarningsFromSignatureResult(XmlSignature signatureResult) {
    for (String warning : new ArrayList<>(signatureResult.getWarnings())) {
      if (WARNING_MESSAGES_TO_IGNORE.contains(warning)) {
        signatureResult.getWarnings().remove(warning);
        LOGGER.debug("Removed false-positive warning message: {}", warning);
      }
    }
  }

  /**
   * DD4J-349
   * Do not accept signatures with signature levels that do not meet the required minimum.
   * See: https://github.com/open-eid/SiVa/blob/release-3.4.1/validation-services-parent/validation-commons/src/main/java/ee/openeid/siva/validation/document/report/builder/ReportBuilderUtils.java#L105-L119
   *
   * @param validationReports validation reports to process
   */
  private static void ensureMinimalRequiredSignatureLevelsAreMet(Reports validationReports) {
    XmlSimpleReport xmlSimpleReport = validationReports.getSimpleReportJaxb();
    for (XmlToken xmlToken : xmlSimpleReport.getSignatureOrTimestamp()) {
      if (xmlToken instanceof XmlSignature) {
        XmlSignature signatureResult = (XmlSignature) xmlToken;
        if (!Indication.TOTAL_PASSED.equals(signatureResult.getIndication())) {
          continue;
        }

        SignatureQualification signatureQualification = Optional
                .ofNullable(signatureResult.getSignatureLevel())
                .map(XmlSignatureLevel::getValue)
                .orElse(null);

        if (signatureQualification != null) {
          LOGGER.debug("Signature level is \"{}\" ({})",
                  signatureQualification.getReadable(),
                  signatureQualification.getLabel()
          );

          if (SIGNATURE_QUALIFICATIONS_OK.contains(signatureQualification)) {
            continue;
          } else if (SIGNATURE_QUALIFICATIONS_WARN.contains(signatureQualification)) {
            signatureResult.getWarnings().add(SIGNATURE_LEVEL_WARNING);
            continue;
          }
        } else {
          LOGGER.warn("No signature level qualification present!");
        }

        signatureResult.setIndication(Indication.TOTAL_FAILED);
        signatureResult.getErrors().add(SIGNATURE_LEVEL_ERROR);
        xmlSimpleReport.setValidSignaturesCount(xmlSimpleReport.getValidSignaturesCount() - 1);
      }
    }
  }

}
