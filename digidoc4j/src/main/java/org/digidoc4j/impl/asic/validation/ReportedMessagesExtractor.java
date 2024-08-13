/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.validation;

import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.CertificateRevokedException;
import org.digidoc4j.exceptions.DigiDoc4JException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A helper class for extracting token validation messages from DSS SimpleReports.
 */
public class ReportedMessagesExtractor {

  private final SimpleReport simpleReport;

  /**
   * Construct an extractor from an instance of {@link Reports}.
   *
   * @param reports DSS reports
   */
  public ReportedMessagesExtractor(Reports reports) {
    this(reports.getSimpleReport());
  }

  /**
   * Construct an extractor from an instance of {@link SimpleReport}.
   *
   * @param simpleReport DSS SimpleReport
   */
  public ReportedMessagesExtractor(SimpleReport simpleReport) {
    this.simpleReport = Objects.requireNonNull(simpleReport);
  }

  /**
   * Extracts and returns the error messages of the specified token.
   *
   * @param tokenUniqueId DSS id of the token to extract error messages for.
   * @return list of extracted error messages
   */
  public List<Message> extractReportedTokenErrors(String tokenUniqueId) {
    return Stream.concat(
                    Optional
                            .ofNullable(simpleReport.getAdESValidationErrors(tokenUniqueId))
                            .map(Collection::stream)
                            .orElseGet(Stream::empty),
                    Optional
                            .ofNullable(simpleReport.getQualificationErrors(tokenUniqueId))
                            .map(Collection::stream)
                            .orElseGet(Stream::empty)
            )
            .filter(Objects::nonNull)
            .map(messageTransformer(tokenUniqueId))
            .collect(Collectors.toCollection(ArrayList::new));
  }

  /**
   * Extracts and returns the warning messages of the specified token.
   *
   * @param tokenUniqueId DSS id of the token to extract warning messages for.
   * @return list of extracted warning messages
   */
  public List<Message> extractReportedTokenWarnings(String tokenUniqueId) {
    return Stream.concat(
                    Optional
                            .ofNullable(simpleReport.getAdESValidationWarnings(tokenUniqueId))
                            .map(Collection::stream)
                            .orElseGet(Stream::empty),
                    Optional
                            .ofNullable(simpleReport.getQualificationWarnings(tokenUniqueId))
                            .map(Collection::stream)
                            .orElseGet(Stream::empty)
            )
            .filter(Objects::nonNull)
            .map(messageTransformer(tokenUniqueId))
            .collect(Collectors.toCollection(ArrayList::new));
  }

  /**
   * Extracts and returns the error messages of signature timestamps of the specified signature.
   *
   * @param signatureUniqueId DSS id of the signature to extract error messages for.
   * @return list of extracted error messages
   */
  public List<Message> extractReportedSignatureTimestampErrors(String signatureUniqueId) {
    return simpleReport.getSignatureTimestamps(signatureUniqueId).stream()
            .flatMap(timestamp -> extractXmlTokenMessages(timestamp, details -> details.getError().stream()))
            .map(xmlMessageTransformer(signatureUniqueId))
            .collect(Collectors.toCollection(ArrayList::new));
  }

  /**
   * Extracts and returns the warning messages of signature timestamps of the specified signature.
   *
   * @param signatureUniqueId DSS id of the signature to extract warning messages for.
   * @return list of extracted warning messages
   */
  public List<Message> extractReportedSignatureTimestampWarnings(String signatureUniqueId) {
    return simpleReport.getSignatureTimestamps(signatureUniqueId).stream()
            .flatMap(timestamp -> extractXmlTokenMessages(timestamp, details -> details.getWarning().stream()))
            .map(xmlMessageTransformer(signatureUniqueId))
            .collect(Collectors.toCollection(ArrayList::new));
  }

  /**
   * Collects extracted error messages as unique list and converts them to {@link DigiDoc4JException}s.
   *
   * @param errorMessages lists of error messages to collect and convert to exceptions
   * @return list of exceptions collected from unique error messages
   */
  @SafeVarargs
  public static List<DigiDoc4JException> collectErrorsAsExceptions(List<Message>... errorMessages) {
    return Stream.of(errorMessages)
            .flatMap(Collection::stream)
            .filter(errorMessage -> StringUtils.isNotBlank(errorMessage.getValue()))
            .distinct()
            .map(errorMessage -> {
              String messageValue = errorMessage.getValue();
              if (StringUtils.equalsAny(errorMessage.getKey(), MessageTag.BBB_XCV_ISCR_ANS.getId(), MessageTag.PSV_IPSVC_ANS.getId())) {
                return new CertificateRevokedException(messageValue, errorMessage.getId());
              } else {
                return new DigiDoc4JException(messageValue, errorMessage.getId());
              }
            })
            .collect(Collectors.toCollection(ArrayList::new));
  }

  /**
   * Collects extracted warning messages as unique list and converts them to {@link DigiDoc4JException}s.
   *
   * @param warningMessages lists of warning messages to collect and convert to exceptions
   * @return list of exceptions collected from unique warning messages
   */
  @SafeVarargs
  public static List<DigiDoc4JException> collectWarningsAsExceptions(List<Message>... warningMessages) {
    return Stream.of(warningMessages)
            .flatMap(Collection::stream)
            .filter(errorMessage -> StringUtils.isNotBlank(errorMessage.getValue()))
            .distinct()
            .map(warningMessage -> new DigiDoc4JException(warningMessage.getValue(), warningMessage.getId()))
            .collect(Collectors.toCollection(ArrayList::new));
  }

  private static Stream<XmlMessage> extractXmlTokenMessages(XmlToken token, Function<XmlDetails, Stream<XmlMessage>> messageExtractor) {
        return (token != null) ? Stream.concat(
                Optional
                        .ofNullable(token.getAdESValidationDetails()).map(messageExtractor).orElseGet(Stream::empty),
                Optional
                        .ofNullable(token.getQualificationDetails()).map(messageExtractor).orElseGet(Stream::empty)
        ) : Stream.empty();
  }

  private static Function<eu.europa.esig.dss.jaxb.object.Message, Message> messageTransformer(String tokenUniqueId) {
    return message -> new Message(message.getKey(), message.getValue(), tokenUniqueId);
  }

  private static Function<XmlMessage, Message> xmlMessageTransformer(String tokenUniqueId) {
    return message -> new Message(message.getKey(), message.getValue(), tokenUniqueId);
  }

  /**
   * An immutable encapsulation for the key (message tag) and the value (message text) of a single error/warning message,
   * and the ID of the token where this message originated from.
   */
  public static class Message {

    private final String key;
    private final String value;
    private final String id;

    public Message(String key, String value, String id) {
      this.key = key;
      this.value = value;
      this.id = id;
    }

    public String getKey() {
      return key;
    }

    public String getValue() {
      return value;
    }

    public String getId() {
      return id;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o instanceof Message) {
        Message message = (Message) o;
        return Objects.equals(key, message.key)
                && Objects.equals(value, message.value)
                && Objects.equals(id, message.id);
      }
      return false;
    }

    @Override
    public int hashCode() {
      return Objects.hash(key, value, id);
    }

  }

}
