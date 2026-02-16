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
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import eu.europa.esig.dss.validation.reports.Reports;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.AbstractContainerValidationResult;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.digidoc4j.impl.asic.asics.TimestampNotGrantedValidationUtils.NOT_GRANTED_CONTAINER_WARNING;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class TimestampNotGrantedValidationUtilsTest {

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenSimpleReportHasNoTokens_NothingChanged() {
    XmlSimpleReport simpleReport = mockSimpleReportWithTokens();
    Reports reports = mockReports(simpleReport);

    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);

    verify(reports).getSimpleReportJaxb();
    verify(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    verifyNoMoreInteractions(reports, simpleReport);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenSimpleReportHasNullToken_NothingChanged() {
    XmlSimpleReport simpleReport = mockSimpleReportWithTokens(Collections.singletonList(null));
    Reports reports = mockReports(simpleReport);

    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);

    verify(reports).getSimpleReportJaxb();
    verify(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    verifyNoMoreInteractions(reports, simpleReport);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenSimpleReportHasSignatureToken_NoInteractionWithToken() {
    XmlSignature signature = mock(XmlSignature.class);
    XmlSimpleReport simpleReport = mockSimpleReportWithTokens(Collections.singletonList(signature));
    Reports reports = mockReports(simpleReport);

    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);

    verify(reports).getSimpleReportJaxb();
    verify(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    verifyNoMoreInteractions(reports, simpleReport);
    verifyNoInteractions(signature);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenSimpleReportHasEvidenceRecordToken_NoInteractionWithToken() {
    XmlEvidenceRecord evidenceRecord = mock(XmlEvidenceRecord.class);
    XmlSimpleReport simpleReport = mockSimpleReportWithTokens(Collections.singletonList(evidenceRecord));
    Reports reports = mockReports(simpleReport);

    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);

    verify(reports).getSimpleReportJaxb();
    verify(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    verifyNoMoreInteractions(reports, simpleReport);
    verifyNoInteractions(evidenceRecord);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenSimpleReportHasTotalPassedTimestamp_NoFurtherInteraction() {
    convertNotGrantedErrorsToWarnings_WhenSimpleReportHasNonPassedTimestamp_NoFurtherInteraction(Indication.TOTAL_PASSED);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenSimpleReportHasTotalFailedTimestamp_NoFurtherInteraction() {
    convertNotGrantedErrorsToWarnings_WhenSimpleReportHasNonPassedTimestamp_NoFurtherInteraction(Indication.TOTAL_FAILED);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenSimpleReportHasIndeterminateTimestamp_NoFurtherInteraction() {
    convertNotGrantedErrorsToWarnings_WhenSimpleReportHasNonPassedTimestamp_NoFurtherInteraction(Indication.INDETERMINATE);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenSimpleReportHasFailedTimestamp_NoFurtherInteraction() {
    convertNotGrantedErrorsToWarnings_WhenSimpleReportHasNonPassedTimestamp_NoFurtherInteraction(Indication.FAILED);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void convertNotGrantedErrorsToWarnings_WhenSimpleReportHasNonPassedTimestamp_NoFurtherInteraction(Indication indication) {
    XmlTimestamp timestamp = mock(XmlTimestamp.class);
    doReturn(indication).when(timestamp).getIndication();
    XmlSimpleReport simpleReport = mockSimpleReportWithTokens(Collections.singletonList(timestamp));
    Reports reports = mockReports(simpleReport);

    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);

    verify(reports).getSimpleReportJaxb();
    verify(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    verify(timestamp).getIndication();
    verifyNoMoreInteractions(reports, simpleReport, timestamp);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenPassedTimestampHasNotGrantedErrorInAdesDetailsBlock_NothingChanged() {
    XmlTimestamp timestamp = createXmlTimestampWithIndication(Indication.PASSED);
    XmlMessage notGrantedMessage = createXmlMessage(
            MessageTag.QUAL_HAS_GRANTED_AT_ANS.getId(),
            new I18nProvider().getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    );
    timestamp.setAdESValidationDetails(createXmlDetailsWithErrors(notGrantedMessage));
    XmlSimpleReport simpleReport = mockSimpleReportWithTokens(Collections.singletonList(timestamp));
    Reports reports = mockReports(simpleReport);

    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);

    assertThat(timestamp.getAdESValidationDetails(), notNullValue());
    assertThat(timestamp.getAdESValidationDetails().getError(), equalTo(Collections.singletonList(notGrantedMessage)));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), empty());
    assertThat(timestamp.getAdESValidationDetails().getInfo(), empty());
    assertThat(timestamp.getQualificationDetails(), nullValue());
    verify(reports).getSimpleReportJaxb();
    verify(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    verifyNoMoreInteractions(reports, simpleReport);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenPassedTimestampHasUnrelatedErrorInQualificationBlock_NothingChanged() {
    XmlTimestamp timestamp = createXmlTimestampWithIndication(Indication.PASSED);
    XmlMessage testMessage = createXmlMessage("TEST", "Some test message");
    timestamp.setQualificationDetails(createXmlDetailsWithErrors(testMessage));
    XmlSimpleReport simpleReport = mockSimpleReportWithTokens(Collections.singletonList(timestamp));
    Reports reports = mockReports(simpleReport);

    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);

    assertThat(timestamp.getAdESValidationDetails(), nullValue());
    assertThat(timestamp.getQualificationDetails(), notNullValue());
    assertThat(timestamp.getQualificationDetails().getError(), equalTo(Collections.singletonList(testMessage)));
    assertThat(timestamp.getQualificationDetails().getWarning(), empty());
    assertThat(timestamp.getQualificationDetails().getInfo(), empty());
    verify(reports).getSimpleReportJaxb();
    verify(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    verifyNoMoreInteractions(reports, simpleReport);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenPassedTimestampHasNotGrantedErrorInQualificationBlock_ConvertsToWarning() {
    XmlTimestamp timestamp = createXmlTimestampWithIndication(Indication.PASSED);
    XmlMessage notGrantedMessage = createXmlMessage(
            MessageTag.QUAL_HAS_GRANTED_AT_ANS.getId(),
            new I18nProvider().getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    );
    timestamp.setQualificationDetails(createXmlDetailsWithErrors(notGrantedMessage));
    XmlSimpleReport simpleReport = mockSimpleReportWithTokens(Collections.singletonList(timestamp));
    Reports reports = mockReports(simpleReport);

    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);

    assertThat(timestamp.getAdESValidationDetails(), nullValue());
    assertThat(timestamp.getQualificationDetails(), notNullValue());
    assertThat(timestamp.getQualificationDetails().getError(), empty());
    assertThat(timestamp.getQualificationDetails().getWarning(), equalTo(Collections.singletonList(notGrantedMessage)));
    assertThat(timestamp.getQualificationDetails().getInfo(), empty());
    verify(reports).getSimpleReportJaxb();
    verify(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    verifyNoMoreInteractions(reports, simpleReport);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenPassedTimestampHasNotGrantedErrorInQualificationBlockButAlsoQualificationWarnings_ConvertsToWarning() {
    XmlTimestamp timestamp = createXmlTimestampWithIndication(Indication.PASSED);
    XmlMessage notGrantedMessage = createXmlMessage(
            MessageTag.QUAL_HAS_GRANTED_AT_ANS.getId(),
            new I18nProvider().getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    );
    timestamp.setQualificationDetails(createXmlDetailsWithErrors(notGrantedMessage));
    XmlMessage testMessage = createXmlMessage("TEST", "Some test message");
    timestamp.getQualificationDetails().getWarning().add(testMessage);
    XmlSimpleReport simpleReport = mockSimpleReportWithTokens(Collections.singletonList(timestamp));
    Reports reports = mockReports(simpleReport);

    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);

    assertThat(timestamp.getAdESValidationDetails(), nullValue());
    assertThat(timestamp.getQualificationDetails(), notNullValue());
    assertThat(timestamp.getQualificationDetails().getError(), empty());
    assertThat(timestamp.getQualificationDetails().getWarning(), equalTo(Arrays.asList(testMessage, notGrantedMessage)));
    assertThat(timestamp.getQualificationDetails().getInfo(), empty());
    verify(reports).getSimpleReportJaxb();
    verify(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    verifyNoMoreInteractions(reports, simpleReport);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenPassedTimestampHasNotGrantedErrorInQualificationBlockButAlsoAdesErrors_NothingChanged() {
    XmlTimestamp timestamp = createXmlTimestampWithIndication(Indication.PASSED);
    XmlMessage testMessage = createXmlMessage("TEST", "Some test message");
    timestamp.setAdESValidationDetails(createXmlDetailsWithErrors(testMessage));
    XmlMessage notGrantedMessage = createXmlMessage(
            MessageTag.QUAL_HAS_GRANTED_AT_ANS.getId(),
            new I18nProvider().getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    );
    timestamp.setQualificationDetails(createXmlDetailsWithErrors(notGrantedMessage));
    XmlSimpleReport simpleReport = mockSimpleReportWithTokens(Collections.singletonList(timestamp));
    Reports reports = mockReports(simpleReport);

    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);

    assertThat(timestamp.getAdESValidationDetails(), notNullValue());
    assertThat(timestamp.getAdESValidationDetails().getError(), equalTo(Collections.singletonList(testMessage)));
    assertThat(timestamp.getAdESValidationDetails().getWarning(), empty());
    assertThat(timestamp.getAdESValidationDetails().getInfo(), empty());
    assertThat(timestamp.getQualificationDetails(), notNullValue());
    assertThat(timestamp.getQualificationDetails().getError(), equalTo(Collections.singletonList(notGrantedMessage)));
    assertThat(timestamp.getQualificationDetails().getWarning(), empty());
    assertThat(timestamp.getQualificationDetails().getInfo(), empty());
    verify(reports).getSimpleReportJaxb();
    verify(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    verifyNoMoreInteractions(reports, simpleReport);
  }

  @Test
  public void convertNotGrantedErrorsToWarnings_WhenPassedTimestampHasNotGrantedErrorAndOtherErrorsInQualificationBlock_NothingChanged() {
    XmlTimestamp timestamp = createXmlTimestampWithIndication(Indication.PASSED);
    XmlMessage notGrantedMessage = createXmlMessage(
            MessageTag.QUAL_HAS_GRANTED_AT_ANS.getId(),
            new I18nProvider().getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    );
    XmlMessage testMessage = createXmlMessage("TEST", "Some test message");
    timestamp.setQualificationDetails(createXmlDetailsWithErrors(notGrantedMessage, testMessage));
    XmlSimpleReport simpleReport = mockSimpleReportWithTokens(Collections.singletonList(timestamp));
    Reports reports = mockReports(simpleReport);

    TimestampNotGrantedValidationUtils.convertNotGrantedErrorsToWarnings(reports);

    assertThat(timestamp.getAdESValidationDetails(), nullValue());
    assertThat(timestamp.getQualificationDetails(), notNullValue());
    assertThat(timestamp.getQualificationDetails().getError(), equalTo(Arrays.asList(notGrantedMessage, testMessage)));
    assertThat(timestamp.getQualificationDetails().getWarning(), empty());
    assertThat(timestamp.getQualificationDetails().getInfo(), empty());
    verify(reports).getSimpleReportJaxb();
    verify(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    verifyNoMoreInteractions(reports, simpleReport);
  }

  @Test
  public void addContainerWarningIfNotGrantedTimestampExists_WhenWarningsIsNull_NothingChanged() {
    AbstractContainerValidationResult containerValidationResult = mock(AbstractContainerValidationResult.class);
    doReturn(null).when(containerValidationResult).getWarnings();

    TimestampNotGrantedValidationUtils.addContainerWarningIfNotGrantedTimestampExists(containerValidationResult);

    verify(containerValidationResult).getWarnings();
    verifyNoMoreInteractions(containerValidationResult);
  }

  @Test
  public void addContainerWarningIfNotGrantedTimestampExists_WhenWarningsIsEmpty_NothingChanged() {
    AbstractContainerValidationResult containerValidationResult = mock(AbstractContainerValidationResult.class);
    doReturn(Collections.emptyList()).when(containerValidationResult).getWarnings();

    TimestampNotGrantedValidationUtils.addContainerWarningIfNotGrantedTimestampExists(containerValidationResult);

    verify(containerValidationResult).getWarnings();
    verifyNoMoreInteractions(containerValidationResult);
  }

  @Test
  public void addContainerWarningIfNotGrantedTimestampExists_WhenWarningsContainsUnrelatedWarning_NothingChanged() {
    AbstractContainerValidationResult containerValidationResult = mock(AbstractContainerValidationResult.class);
    DigiDoc4JException unrelatedWarning = new DigiDoc4JException("Unrelated warning message");
    doReturn(Collections.singletonList(unrelatedWarning)).when(containerValidationResult).getWarnings();

    TimestampNotGrantedValidationUtils.addContainerWarningIfNotGrantedTimestampExists(containerValidationResult);

    verify(containerValidationResult).getWarnings();
    verifyNoMoreInteractions(containerValidationResult);
  }

  @Test
  public void addContainerWarningIfNotGrantedTimestampExists_WhenWarningsContainsNotGrantedWarning_ContainerWarningIsAdded() {
    AbstractContainerValidationResult containerValidationResult = mock(AbstractContainerValidationResult.class);
    DigiDoc4JException notGrantedWarning = new DigiDoc4JException(
            new I18nProvider().getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
    );
    doReturn(Collections.singletonList(notGrantedWarning)).when(containerValidationResult).getWarnings();

    TimestampNotGrantedValidationUtils.addContainerWarningIfNotGrantedTimestampExists(containerValidationResult);

    verify(containerValidationResult).getWarnings();
    ArgumentCaptor<List<DigiDoc4JException>> warningListCaptor = createDigiDoc4jExceptionListCaptor();
    verify(containerValidationResult).addContainerWarnings(warningListCaptor.capture());
    assertThat(warningListCaptor.getValue(), hasSize(1));
    assertThat(warningListCaptor.getValue().get(0).getClass(), equalTo(DigiDoc4JException.class));
    assertThat(warningListCaptor.getValue().get(0).getMessage(), equalTo(NOT_GRANTED_CONTAINER_WARNING));
    verifyNoMoreInteractions(containerValidationResult);
  }

  @Test
  public void addContainerWarningIfNotGrantedTimestampExists_WhenWarningsContainsNotGrantedWarningsAmongOthers_ContainerWarningIsAdded() {
    AbstractContainerValidationResult containerValidationResult = mock(AbstractContainerValidationResult.class);
    doReturn(Collections.unmodifiableList(Arrays.asList(
            new DigiDoc4JException("Unrelated warning 1"),
            new DigiDoc4JException(
                    new I18nProvider().getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
            ),
            new DigiDoc4JException("Unrelated warning 2"),
            new DigiDoc4JException(
                    new I18nProvider().getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)
            ),
            new DigiDoc4JException("Unrelated warning 3")
    ))).when(containerValidationResult).getWarnings();

    TimestampNotGrantedValidationUtils.addContainerWarningIfNotGrantedTimestampExists(containerValidationResult);

    verify(containerValidationResult).getWarnings();
    ArgumentCaptor<List<DigiDoc4JException>> warningListCaptor = createDigiDoc4jExceptionListCaptor();
    verify(containerValidationResult).addContainerWarnings(warningListCaptor.capture());
    assertThat(warningListCaptor.getValue(), hasSize(1));
    assertThat(warningListCaptor.getValue().get(0).getClass(), equalTo(DigiDoc4JException.class));
    assertThat(warningListCaptor.getValue().get(0).getMessage(), equalTo(NOT_GRANTED_CONTAINER_WARNING));
    verifyNoMoreInteractions(containerValidationResult);
  }

  private static XmlMessage createXmlMessage(String key, String value) {
    XmlMessage message = new XmlMessage();
    message.setKey(key);
    message.setValue(value);
    return message;
  }

  private static XmlDetails createXmlDetailsWithErrors(XmlMessage... errors) {
    return createXmlDetailsWithErrors(Arrays.asList(errors));
  }

  private static XmlDetails createXmlDetailsWithErrors(List<XmlMessage> errors) {
    XmlDetails details = new XmlDetails();
    details.getError().addAll(errors);
    return details;
  }

  private static XmlDetails createXmlDetailsWithWarnings(XmlMessage... warnings) {
    return createXmlDetailsWithWarnings(Arrays.asList(warnings));
  }

  private static XmlDetails createXmlDetailsWithWarnings(List<XmlMessage> warnings) {
    XmlDetails details = new XmlDetails();
    details.getWarning().addAll(warnings);
    return details;
  }

  private static XmlTimestamp createXmlTimestampWithIndication(Indication indication) {
    XmlTimestamp timestamp = new XmlTimestamp();
    timestamp.setIndication(indication);
    return timestamp;
  }

  @SuppressWarnings("unchecked")
  private static ArgumentCaptor<List<DigiDoc4JException>> createDigiDoc4jExceptionListCaptor() {
    return ArgumentCaptor.forClass(List.class);
  }

  private static XmlSimpleReport mockSimpleReportWithTokens(XmlToken... tokens) {
    return mockSimpleReportWithTokens(Arrays.asList(tokens));
  }

  private static XmlSimpleReport mockSimpleReportWithTokens(List<XmlToken> tokens) {
    XmlSimpleReport simpleReport = mock(XmlSimpleReport.class);
    doReturn(tokens).when(simpleReport).getSignatureOrTimestampOrEvidenceRecord();
    return simpleReport;
  }

  private static Reports mockReports(XmlSimpleReport simpleReport) {
    Reports reports = mock(Reports.class);
    doReturn(simpleReport).when(reports).getSimpleReportJaxb();
    return reports;
  }

}
