package org.digidoc4j.impl.asic.xades;

import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.commons.collections4.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class XadesValidationReportProcessor {

  private static final Logger LOGGER = LoggerFactory.getLogger(XadesValidationReportProcessor.class);
  private static final I18nProvider i18nProvider = new I18nProvider();
  private static final List<String> WARNING_MESSAGES_TO_IGNORE = Arrays.asList(
          i18nProvider.getMessage(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1),      // DD4J - 404
          i18nProvider.getMessage(MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2)      // DD4J - 404
  );

  public static void process(Reports validationReports) {
    removeFalsePositiveWarningsFromValidationReports(validationReports);
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
    removeFalsePositiveWarningsFromToken(signatureResult);
    if (signatureResult.getTimestamps() != null && CollectionUtils.isNotEmpty(signatureResult.getTimestamps().getTimestamp())) {
      for (XmlTimestamp timestampResult : signatureResult.getTimestamps().getTimestamp()) {
        if (timestampResult != null) {
          removeFalsePositiveWarningsFromToken(timestampResult);
        }
      }
    }
  }

  private static void removeFalsePositiveWarningsFromToken(XmlToken token) {
    if (token.getAdESValidationDetails() != null) {
      removeFalsePositiveWarningsFromDetails(token.getAdESValidationDetails());
    }
    if (token.getQualificationDetails() != null) {
      removeFalsePositiveWarningsFromDetails(token.getQualificationDetails());
    }
  }

  private static void removeFalsePositiveWarningsFromDetails(XmlDetails details) {
    for (XmlMessage warning : new ArrayList<>(details.getWarning())) {
      if (WARNING_MESSAGES_TO_IGNORE.contains(warning.getValue())) {
        details.getWarning().remove(warning);
        LOGGER.debug("Removed false-positive warning message: \"{}\":\"{}\"", warning.getKey(), warning.getValue());
      }
    }
  }
}
