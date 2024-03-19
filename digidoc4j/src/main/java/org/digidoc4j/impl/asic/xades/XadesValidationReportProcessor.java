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

import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

public class XadesValidationReportProcessor {

  private static final Logger LOGGER = LoggerFactory.getLogger(XadesValidationReportProcessor.class);

  private static final I18nProvider I18N_PROVIDER = new I18nProvider();
  private static final List<String> WARNING_MESSAGES_TO_IGNORE = Collections.unmodifiableList(Arrays.asList(
          MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1.getId(),      // DD4J-404
          MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2.getId()      // DD4J-404
  ));
  private static final String TST_POE_TIME_MESSAGE = I18N_PROVIDER.getMessage(MessageTag.VT_TST_POE_TIME); // DD4J-986

  private static final List<TokenProcessor> TOKEN_PROCESSORS = Collections.unmodifiableList(Arrays.asList(
          /*
           * DD4J-404
           * Remove warning messages from DSS reports that are considered false-positive by DDJ4 or uncorrectable
           * at the given time.
           * Messages are removed from both AdESValidationDetails and QualificationDetails blocks of both signatures
           * and their timestamps.
           */
          new MessageRemovingSignatureAndTimestampProcessor(
                  Collections.unmodifiableList(Arrays.asList(
                          XmlToken::getAdESValidationDetails,
                          XmlToken::getQualificationDetails
                  )),
                  Collections.singletonList(XmlDetails::getWarning),
                  m -> WARNING_MESSAGES_TO_IGNORE.contains(m.getKey())
          ),
          /*
           * DD4J-986
           * Remove timestamping service status at POE time error messages that are considered false-positives in
           * Estonian context.
           * Messages are removed from the QualificationDetails block of signature timestamps.
           * Messages are matched by first matching the message key to "QUAL_HAS_GRANTED_AT_ANS" and then checking
           * whether the message value contains the value of "VT_TST_POE_TIME".
           */
          new MessageRemovingSignatureTimestampProcessor(
                  Collections.singletonList(XmlToken::getQualificationDetails),
                  Collections.singletonList(XmlDetails::getError),
                  m -> MessageTag.QUAL_HAS_GRANTED_AT_ANS.getId().equals(m.getKey())
                            && StringUtils.contains(m.getValue(), TST_POE_TIME_MESSAGE)
          )
  ));

  public static void process(Reports validationReports) {
    processTokensInSimpleReport(validationReports.getSimpleReportJaxb());
  }

  private static void processTokensInSimpleReport(XmlSimpleReport simpleReport) {
    for (final XmlToken token : simpleReport.getSignatureOrTimestampOrEvidenceRecord()) {
      for (final TokenProcessor tokenProcessor : TOKEN_PROCESSORS) {
        tokenProcessor.processToken(token);
      }
    }
  }

  private static void forEachSignatureTimestamp(XmlSignature signature, Consumer<XmlTimestamp> timestampProcessor) {
    Optional
            .ofNullable(signature.getTimestamps())
            .map(XmlTimestamps::getTimestamp)
            .orElseGet(Collections::emptyList)
            .forEach(timestampProcessor);
  }

  @FunctionalInterface
  private interface TokenProcessor {
    void processToken(XmlToken token);
  }

  private abstract static class MessageRemovingTokenProcessor implements TokenProcessor {

    private final List<Function<XmlToken, XmlDetails>> detailsExtractors;
    private final List<Function<XmlDetails, List<XmlMessage>>> messageListExtractors;
    private final Predicate<XmlMessage> messageMatcher;

    protected MessageRemovingTokenProcessor(
            List<Function<XmlToken, XmlDetails>> detailsExtractors,
            List<Function<XmlDetails, List<XmlMessage>>> messageListExtractors,
            Predicate<XmlMessage> messageMatcher
    ) {
      this.detailsExtractors = Objects.requireNonNull(detailsExtractors);
      this.messageListExtractors = Objects.requireNonNull(messageListExtractors);
      this.messageMatcher = Objects.requireNonNull(messageMatcher);
    }

    @Override
    public void processToken(final XmlToken token) {
      for (final Function<XmlToken, XmlDetails> detailsExtractor : detailsExtractors) {
        final XmlDetails details = detailsExtractor.apply(token);
        if (details != null) {
          processDetails(details);
        }
      }
    }

    private void processDetails(final XmlDetails details) {
      for (final Function<XmlDetails, List<XmlMessage>> messageListExtractor : messageListExtractors) {
        final List<XmlMessage> messageList = messageListExtractor.apply(details);
        if (CollectionUtils.isNotEmpty(messageList)) {
          processMessageList(messageList);
        }
      }
    }

    private void processMessageList(final List<XmlMessage> messageList) {
      final Iterator<XmlMessage> messageIterator = messageList.iterator();
      while (messageIterator.hasNext()) {
        final XmlMessage message = messageIterator.next();
        if (messageMatcher.test(message)) {
          messageIterator.remove();
          LOGGER.debug("Removed false-positive message: \"{}\":\"{}\"", message.getKey(), message.getValue());
        }
      }
    }

  }

  private static class MessageRemovingSignatureAndTimestampProcessor extends MessageRemovingTokenProcessor {

    public MessageRemovingSignatureAndTimestampProcessor(
            List<Function<XmlToken, XmlDetails>> detailsExtractors,
            List<Function<XmlDetails, List<XmlMessage>>> messageListExtractors,
            Predicate<XmlMessage> messageMatcher
    ) {
      super(detailsExtractors, messageListExtractors, messageMatcher);
    }

    @Override
    public void processToken(final XmlToken token) {
      if (token instanceof XmlSignature) {
        super.processToken(token);
        forEachSignatureTimestamp((XmlSignature) token, super::processToken);
      }
    }

  }

  private static class MessageRemovingSignatureTimestampProcessor extends MessageRemovingTokenProcessor {

    public MessageRemovingSignatureTimestampProcessor(
            List<Function<XmlToken, XmlDetails>> detailsExtractors,
            List<Function<XmlDetails, List<XmlMessage>>> messageListExtractors,
            Predicate<XmlMessage> messageMatcher
    ) {
      super(detailsExtractors, messageListExtractors, messageMatcher);
    }

    @Override
    public void processToken(final XmlToken token) {
      if (token instanceof XmlSignature) {
        forEachSignatureTimestamp((XmlSignature) token, super::processToken);
      }
    }

  }

}
