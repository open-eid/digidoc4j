/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.AbstractContainerValidationResult;

import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

final class TimestampNotGrantedValidationUtils {

  private static final String NOT_GRANTED_AT_MESSAGE_TAG = MessageTag.QUAL_HAS_GRANTED_AT_ANS.getId();
  private static final String NOT_GRANTED_AT_TST_POE_TIME_MESSAGE_TEXT = new I18nProvider()
          .getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME);

  private static final Predicate<String> NOT_GRANTED_TEXT_PREDICATE = NOT_GRANTED_AT_TST_POE_TIME_MESSAGE_TEXT::equals;
  private static final Predicate<XmlMessage> NOT_GRANTED_MESSAGE_PREDICATE = message -> message != null &&
          NOT_GRANTED_AT_MESSAGE_TAG.equals(message.getKey()) && NOT_GRANTED_TEXT_PREDICATE.test(message.getValue());

  static final String NOT_GRANTED_CONTAINER_WARNING = "Found a timestamp token not related to granted status."
          + " If not yet covered with a fresh timestamp token, this container might become invalid in the future.";

  static void convertNotGrantedErrorsToWarnings(Reports reports) {
    doForEachTimestampInSimpleReportJaxb(reports, timestamp -> {
      if (isValidWithOneQualificationError(timestamp)) {
        convertErrorsToWarnings(timestamp.getQualificationDetails(), NOT_GRANTED_MESSAGE_PREDICATE);
      }
    });
  }

  static void addContainerWarningIfNotGrantedTimestampExists(AbstractContainerValidationResult validationResult) {
    if (containsMessage(validationResult.getWarnings(), DigiDoc4JException::getMessage, NOT_GRANTED_TEXT_PREDICATE)) {
      DigiDoc4JException warning = new DigiDoc4JException(NOT_GRANTED_CONTAINER_WARNING);
      validationResult.addContainerWarnings(Collections.singletonList(warning));
    }
  }

  private static void doForEachTimestampInSimpleReportJaxb(Reports reports, Consumer<XmlTimestamp> timestampProcessor) {
    for (XmlToken token : reports.getSimpleReportJaxb().getSignatureOrTimestampOrEvidenceRecord()) {
      if (token instanceof XmlTimestamp) {
        timestampProcessor.accept((XmlTimestamp) token);
      }
    }
  }

  private static boolean isValidWithOneQualificationError(XmlTimestamp timestamp) {
    return Indication.PASSED.equals(timestamp.getIndication()) &&
            hasNoErrors(timestamp.getAdESValidationDetails()) &&
            getErrorCount(timestamp.getQualificationDetails()) == 1;
  }

  private static void convertErrorsToWarnings(XmlDetails details, Predicate<XmlMessage> messageFilter) {
    if (details == null || CollectionUtils.isEmpty(details.getError())) {
      return;
    }

    Iterator<XmlMessage> errorsIterator = details.getError().iterator();

    while (errorsIterator.hasNext()) {
      XmlMessage errorMessage = errorsIterator.next();

      if (messageFilter.test(errorMessage)) {
        errorsIterator.remove();
        details.getWarning().add(errorMessage);
      }
    }
  }

  private static boolean hasErrors(XmlDetails details) {
    return (details != null) && CollectionUtils.isNotEmpty(details.getError());
  }

  private static boolean hasNoErrors(XmlDetails details) {
    return !hasErrors(details);
  }

  private static int getErrorCount(XmlDetails details) {
    return (details != null)
            ? CollectionUtils.size(details.getError())
            : 0;
  }

  private static <E> boolean containsMessage(
          Collection<E> collection,
          Function<E, String> messageMapper,
          Predicate<String> messageFilter
  ) {
    return CollectionUtils.isNotEmpty(collection) && collection.stream()
            .filter(Objects::nonNull)
            .map(messageMapper)
            .filter(Objects::nonNull)
            .anyMatch(messageFilter);
  }

  private TimestampNotGrantedValidationUtils() {
  }

}
