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
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.validation.reports.Reports;
import org.digidoc4j.exceptions.CertificateRevokedException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class ReportedMessagesExtractorTest {

  private static final String TOKEN_UNIQUE_ID = "tokenUniqueId";

  @Test
  public void construct_WhenSimpleReportIsNull_ThrowsNullPointerException() {
    assertThrows(
            NullPointerException.class,
            () -> new ReportedMessagesExtractor((SimpleReport) null)
    );
  }

  @Test
  public void construct_WhenSimpleReportInReportsIsNull_ThrowsNullPointerException() {
    Reports reports = mock(Reports.class);
    doReturn(null).when(reports).getSimpleReport();

    assertThrows(
            NullPointerException.class,
            () -> new ReportedMessagesExtractor((SimpleReport) null)
    );
  }

  @Test
  public void extractReportedTokenErrors_WhenErrorListsAreNull_EmptyListIsReturned() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    doReturn(null).when(simpleReport).getAdESValidationErrors(TOKEN_UNIQUE_ID);
    doReturn(null).when(simpleReport).getQualificationErrors(TOKEN_UNIQUE_ID);

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedTokenErrors(TOKEN_UNIQUE_ID);

    assertThat(result, empty());
    verify(simpleReport).getAdESValidationErrors(TOKEN_UNIQUE_ID);
    verify(simpleReport).getQualificationErrors(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedTokenErrors_WhenOnlyAdesErrorExists_ReturnsGivenAdesError() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    Message dssMessage = new Message("KEY", "VALUE");
    doReturn(Collections.singletonList(dssMessage)).when(simpleReport).getAdESValidationErrors(TOKEN_UNIQUE_ID);
    doReturn(Collections.emptyList()).when(simpleReport).getQualificationErrors(TOKEN_UNIQUE_ID);

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedTokenErrors(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(1));
    assertThat(result, contains(new ReportedMessagesExtractor.Message("KEY", "VALUE", TOKEN_UNIQUE_ID)));
    verify(simpleReport).getAdESValidationErrors(TOKEN_UNIQUE_ID);
    verify(simpleReport).getQualificationErrors(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedTokenErrors_WhenOnlyQualificationErrorExists_ReturnsGivenQualificationError() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    doReturn(Collections.emptyList()).when(simpleReport).getAdESValidationErrors(TOKEN_UNIQUE_ID);
    Message dssMessage = new Message("KEY", "VALUE");
    doReturn(Collections.singletonList(dssMessage)).when(simpleReport).getQualificationErrors(TOKEN_UNIQUE_ID);

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedTokenErrors(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(1));
    assertThat(result, contains(new ReportedMessagesExtractor.Message("KEY", "VALUE", TOKEN_UNIQUE_ID)));
    verify(simpleReport).getAdESValidationErrors(TOKEN_UNIQUE_ID);
    verify(simpleReport).getQualificationErrors(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedTokenErrors_WhenBothAdesAndQualificationErrorsExist_ReturnsGivenErrors() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    Message dssMessage1 = new Message("KEY1", "VALUE1");
    doReturn(Collections.singletonList(dssMessage1)).when(simpleReport).getAdESValidationErrors(TOKEN_UNIQUE_ID);
    Message dssMessage2 = new Message("KEY2", "VALUE2");
    doReturn(Collections.singletonList(dssMessage2)).when(simpleReport).getQualificationErrors(TOKEN_UNIQUE_ID);

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedTokenErrors(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(2));
    assertThat(result, containsInRelativeOrder(
            new ReportedMessagesExtractor.Message("KEY1", "VALUE1", TOKEN_UNIQUE_ID),
            new ReportedMessagesExtractor.Message("KEY2", "VALUE2", TOKEN_UNIQUE_ID)
    ));
    verify(simpleReport).getAdESValidationErrors(TOKEN_UNIQUE_ID);
    verify(simpleReport).getQualificationErrors(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedTokenWarnings_WhenWarningListsAreNull_EmptyListIsReturned() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    doReturn(null).when(simpleReport).getAdESValidationWarnings(TOKEN_UNIQUE_ID);
    doReturn(null).when(simpleReport).getQualificationWarnings(TOKEN_UNIQUE_ID);

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedTokenWarnings(TOKEN_UNIQUE_ID);

    assertThat(result, empty());
    verify(simpleReport).getAdESValidationWarnings(TOKEN_UNIQUE_ID);
    verify(simpleReport).getQualificationWarnings(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedTokenWarnings_WhenOnlyAdesWarningExists_ReturnsGivenAdesWarning() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    Message dssMessage = new Message("KEY", "VALUE");
    doReturn(Collections.singletonList(dssMessage)).when(simpleReport).getAdESValidationWarnings(TOKEN_UNIQUE_ID);
    doReturn(Collections.emptyList()).when(simpleReport).getQualificationWarnings(TOKEN_UNIQUE_ID);

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedTokenWarnings(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(1));
    assertThat(result, contains(new ReportedMessagesExtractor.Message("KEY", "VALUE", TOKEN_UNIQUE_ID)));
    verify(simpleReport).getAdESValidationWarnings(TOKEN_UNIQUE_ID);
    verify(simpleReport).getQualificationWarnings(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedTokenWarnings_WhenOnlyQualificationWarningExists_ReturnsGivenQualificationWarning() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    doReturn(Collections.emptyList()).when(simpleReport).getAdESValidationWarnings(TOKEN_UNIQUE_ID);
    Message dssMessage = new Message("KEY", "VALUE");
    doReturn(Collections.singletonList(dssMessage)).when(simpleReport).getQualificationWarnings(TOKEN_UNIQUE_ID);

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedTokenWarnings(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(1));
    assertThat(result, contains(new ReportedMessagesExtractor.Message("KEY", "VALUE", TOKEN_UNIQUE_ID)));
    verify(simpleReport).getAdESValidationWarnings(TOKEN_UNIQUE_ID);
    verify(simpleReport).getQualificationWarnings(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedTokenWarnings_WhenBothAdesAndQualificationWarningsExist_ReturnsGivenWarnings() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    Message dssMessage1 = new Message("KEY1", "VALUE1");
    doReturn(Collections.singletonList(dssMessage1)).when(simpleReport).getAdESValidationWarnings(TOKEN_UNIQUE_ID);
    Message dssMessage2 = new Message("KEY2", "VALUE2");
    doReturn(Collections.singletonList(dssMessage2)).when(simpleReport).getQualificationWarnings(TOKEN_UNIQUE_ID);

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedTokenWarnings(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(2));
    assertThat(result, containsInRelativeOrder(
            new ReportedMessagesExtractor.Message("KEY1", "VALUE1", TOKEN_UNIQUE_ID),
            new ReportedMessagesExtractor.Message("KEY2", "VALUE2", TOKEN_UNIQUE_ID)
    ));
    verify(simpleReport).getAdESValidationWarnings(TOKEN_UNIQUE_ID);
    verify(simpleReport).getQualificationWarnings(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedSignatureTimestampErrors_WhenSignatureTimestampsIsEmptyList_ReturnsEmptyList() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    doReturn(Collections.emptyList()).when(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedSignatureTimestampErrors(TOKEN_UNIQUE_ID);

    assertThat(result, empty());
    verify(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedSignatureTimestampErrors_WhenSignatureTimestampDetailsAreNull_ReturnsEmptyList() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    XmlTimestamp xmlTimestamp = mock(XmlTimestamp.class);
    doReturn(Collections.singletonList(xmlTimestamp)).when(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    doReturn(null).when(xmlTimestamp).getAdESValidationDetails();
    doReturn(null).when(xmlTimestamp).getQualificationDetails();

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedSignatureTimestampErrors(TOKEN_UNIQUE_ID);

    assertThat(result, empty());
    verify(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedSignatureTimestampErrors_WhenSignatureTimestampHasAdesError_ReturnsGivenError() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    XmlTimestamp xmlTimestamp = mock(XmlTimestamp.class);
    doReturn(Collections.singletonList(xmlTimestamp)).when(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    XmlDetails xmlDetails = createXmlDetailsWithErrors(createXmlMessage("KEY", "VALUE"));
    doReturn(xmlDetails).when(xmlTimestamp).getAdESValidationDetails();
    doReturn(new XmlDetails()).when(xmlTimestamp).getQualificationDetails();

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedSignatureTimestampErrors(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(1));
    assertThat(result, contains(new ReportedMessagesExtractor.Message("KEY", "VALUE", TOKEN_UNIQUE_ID)));
    verify(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedSignatureTimestampErrors_WhenSignatureTimestampHasQualificationError_ReturnsGivenError() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    XmlTimestamp xmlTimestamp = mock(XmlTimestamp.class);
    doReturn(Collections.singletonList(xmlTimestamp)).when(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    doReturn(new XmlDetails()).when(xmlTimestamp).getAdESValidationDetails();
    XmlDetails xmlDetails = createXmlDetailsWithErrors(createXmlMessage("KEY", "VALUE"));
    doReturn(xmlDetails).when(xmlTimestamp).getQualificationDetails();

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedSignatureTimestampErrors(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(1));
    assertThat(result, contains(new ReportedMessagesExtractor.Message("KEY", "VALUE", TOKEN_UNIQUE_ID)));
    verify(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedSignatureTimestampErrors_WhenSignatureTimestampHasBothErrors_ReturnsGivenErrors() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    XmlTimestamp xmlTimestamp = mock(XmlTimestamp.class);
    doReturn(Collections.singletonList(xmlTimestamp)).when(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    XmlDetails xmlDetails1 = createXmlDetailsWithErrors(createXmlMessage("KEY1", "VALUE1"));
    doReturn(xmlDetails1).when(xmlTimestamp).getAdESValidationDetails();
    XmlDetails xmlDetails2 = createXmlDetailsWithErrors(createXmlMessage("KEY2", "VALUE2"));
    doReturn(xmlDetails2).when(xmlTimestamp).getQualificationDetails();

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedSignatureTimestampErrors(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(2));
    assertThat(result, containsInRelativeOrder(
            new ReportedMessagesExtractor.Message("KEY1", "VALUE1", TOKEN_UNIQUE_ID),
            new ReportedMessagesExtractor.Message("KEY2", "VALUE2", TOKEN_UNIQUE_ID)
    ));
    verify(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedSignatureTimestampWarnings_WhenSignatureTimestampsIsEmptyList_ReturnsEmptyList() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    doReturn(Collections.emptyList()).when(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedSignatureTimestampWarnings(TOKEN_UNIQUE_ID);

    assertThat(result, empty());
    verify(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedSignatureTimestampWarnings_WhenSignatureTimestampDetailsAreNull_ReturnsEmptyList() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    XmlTimestamp xmlTimestamp = mock(XmlTimestamp.class);
    doReturn(Collections.singletonList(xmlTimestamp)).when(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    doReturn(null).when(xmlTimestamp).getAdESValidationDetails();
    doReturn(null).when(xmlTimestamp).getQualificationDetails();

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedSignatureTimestampWarnings(TOKEN_UNIQUE_ID);

    assertThat(result, empty());
    verify(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedSignatureTimestampWarning_WhenSignatureTimestampHasAdesWarning_ReturnsGivenWarning() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    XmlTimestamp xmlTimestamp = mock(XmlTimestamp.class);
    doReturn(Collections.singletonList(xmlTimestamp)).when(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    XmlDetails xmlDetails = createXmlDetailsWithWarnings(createXmlMessage("KEY", "VALUE"));
    doReturn(xmlDetails).when(xmlTimestamp).getAdESValidationDetails();
    doReturn(new XmlDetails()).when(xmlTimestamp).getQualificationDetails();

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedSignatureTimestampWarnings(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(1));
    assertThat(result, contains(new ReportedMessagesExtractor.Message("KEY", "VALUE", TOKEN_UNIQUE_ID)));
    verify(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedSignatureTimestampWarnings_WhenSignatureTimestampHasQualificationWarning_ReturnsGivenWarning() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    XmlTimestamp xmlTimestamp = mock(XmlTimestamp.class);
    doReturn(Collections.singletonList(xmlTimestamp)).when(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    doReturn(new XmlDetails()).when(xmlTimestamp).getAdESValidationDetails();
    XmlDetails xmlDetails = createXmlDetailsWithWarnings(createXmlMessage("KEY", "VALUE"));
    doReturn(xmlDetails).when(xmlTimestamp).getQualificationDetails();

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedSignatureTimestampWarnings(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(1));
    assertThat(result, contains(new ReportedMessagesExtractor.Message("KEY", "VALUE", TOKEN_UNIQUE_ID)));
    verify(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void extractReportedSignatureTimestampWarnings_WhenSignatureTimestampHasBothWarnings_ReturnsGivenWarnings() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    ReportedMessagesExtractor extractor = new ReportedMessagesExtractor(simpleReport);
    XmlTimestamp xmlTimestamp = mock(XmlTimestamp.class);
    doReturn(Collections.singletonList(xmlTimestamp)).when(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    XmlDetails xmlDetails1 = createXmlDetailsWithWarnings(createXmlMessage("KEY1", "VALUE1"));
    doReturn(xmlDetails1).when(xmlTimestamp).getAdESValidationDetails();
    XmlDetails xmlDetails2 = createXmlDetailsWithWarnings(createXmlMessage("KEY2", "VALUE2"));
    doReturn(xmlDetails2).when(xmlTimestamp).getQualificationDetails();

    List<ReportedMessagesExtractor.Message> result = extractor.extractReportedSignatureTimestampWarnings(TOKEN_UNIQUE_ID);

    assertThat(result, hasSize(2));
    assertThat(result, containsInRelativeOrder(
            new ReportedMessagesExtractor.Message("KEY1", "VALUE1", TOKEN_UNIQUE_ID),
            new ReportedMessagesExtractor.Message("KEY2", "VALUE2", TOKEN_UNIQUE_ID)
    ));
    verify(simpleReport).getSignatureTimestamps(TOKEN_UNIQUE_ID);
    verifyNoMoreInteractions(simpleReport);
  }

  @Test
  public void collectErrorsAsExceptions_WhenInputIsEmpty_ReturnsEmptyList() {
    List<DigiDoc4JException> result = ReportedMessagesExtractor.collectErrorsAsExceptions();

    assertThat(result, empty());
  }

  @Test
  public void collectErrorsAsExceptions_WhenInputIsEmptyLists_ReturnsEmptyList() {
    List<DigiDoc4JException> result = ReportedMessagesExtractor.collectErrorsAsExceptions(
            Collections.emptyList(),
            Collections.emptyList()
    );

    assertThat(result, empty());
  }

  @Test
  public void collectErrorsAsExceptions_WhenInputContainsMessages_ReturnsListOfCorrespondingExceptions() {
    List<DigiDoc4JException> result = ReportedMessagesExtractor.collectErrorsAsExceptions(Arrays.asList(
            new ReportedMessagesExtractor.Message("KEY1", "VALUE1", "ID1"),
            new ReportedMessagesExtractor.Message("KEY2", "VALUE2", "ID2")
    ));

    assertThat(result, hasSize(2));
    assertThat(result.get(0).getClass(), sameInstance(DigiDoc4JException.class));
    assertThat(result.get(0).getMessage(), equalTo("VALUE1"));
    assertThat(result.get(0).getSignatureId(), equalTo("ID1"));
    assertThat(result.get(1).getClass(), sameInstance(DigiDoc4JException.class));
    assertThat(result.get(1).getMessage(), equalTo("VALUE2"));
    assertThat(result.get(1).getSignatureId(), equalTo("ID2"));
  }

  @Test
  public void collectErrorsAsExceptions_WhenInputContainsMessagesInSeparateLists_ReturnsListOfCorrespondingExceptions() {
    List<DigiDoc4JException> result = ReportedMessagesExtractor.collectErrorsAsExceptions(
            Collections.singletonList(new ReportedMessagesExtractor.Message("KEY1", "VALUE1", "ID1")),
            Collections.singletonList(new ReportedMessagesExtractor.Message("KEY2", "VALUE2", "ID2"))
    );

    assertThat(result, hasSize(2));
    assertThat(result.get(0).getClass(), sameInstance(DigiDoc4JException.class));
    assertThat(result.get(0).getMessage(), equalTo("VALUE1"));
    assertThat(result.get(0).getSignatureId(), equalTo("ID1"));
    assertThat(result.get(1).getClass(), sameInstance(DigiDoc4JException.class));
    assertThat(result.get(1).getMessage(), equalTo("VALUE2"));
    assertThat(result.get(1).getSignatureId(), equalTo("ID2"));
  }

  @Test
  public void collectErrorsAsExceptions_WhenInputContainsCertificateRevocationMessage_ReturnsCertificateRevocationException() {
    Stream.of(MessageTag.BBB_XCV_ISCR_ANS, MessageTag.PSV_IPSVC_ANS).forEach(messageTag -> {
      List<DigiDoc4JException> result = ReportedMessagesExtractor.collectErrorsAsExceptions(Collections.singletonList(
              new ReportedMessagesExtractor.Message(messageTag.getId(), "Whatever message value", "ID")
      ));

      assertThat(result, hasSize(1));
      assertThat(result.get(0).getClass(), sameInstance(CertificateRevokedException.class));
      assertThat(result.get(0).getMessage(), equalTo("Whatever message value"));
      assertThat(result.get(0).getSignatureId(), equalTo("ID"));
    });
  }

  @Test
  public void collectErrorsAsExceptions_WhenInputContainsNonCertificateRevocationMessage_ReturnsBaseException() {
    final Set<MessageTag> exclusions = new HashSet<>(Arrays.asList(MessageTag.BBB_XCV_ISCR_ANS, MessageTag.PSV_IPSVC_ANS));
    Stream.of(MessageTag.values()).filter(mt -> !exclusions.contains(mt)).forEach(messageTag -> {
      List<DigiDoc4JException> result = ReportedMessagesExtractor.collectErrorsAsExceptions(Collections.singletonList(
              new ReportedMessagesExtractor.Message(messageTag.getId(), "Message value", "ID")
      ));

      assertThat(result, hasSize(1));
      assertThat(result.get(0).getClass(), sameInstance(DigiDoc4JException.class));
      assertThat(result.get(0).getMessage(), equalTo("Message value"));
      assertThat(result.get(0).getSignatureId(), equalTo("ID"));
    });
  }

  @Test
  public void collectWarningsAsExceptions_WhenInputIsEmpty_ReturnsEmptyList() {
    List<DigiDoc4JException> result = ReportedMessagesExtractor.collectWarningsAsExceptions();

    assertThat(result, empty());
  }

  @Test
  public void collectWarningsAsExceptions_WhenInputIsEmptyLists_ReturnsEmptyList() {
    List<DigiDoc4JException> result = ReportedMessagesExtractor.collectWarningsAsExceptions(
            Collections.emptyList(),
            Collections.emptyList()
    );

    assertThat(result, empty());
  }

  @Test
  public void collectWarningsAsExceptions_WhenInputContainsMessages_ReturnsListOfCorrespondingExceptions() {
    List<DigiDoc4JException> result = ReportedMessagesExtractor.collectWarningsAsExceptions(Arrays.asList(
            new ReportedMessagesExtractor.Message("KEY1", "VALUE1", "ID1"),
            new ReportedMessagesExtractor.Message("KEY2", "VALUE2", "ID2")
    ));

    assertThat(result, hasSize(2));
    assertThat(result.get(0).getClass(), sameInstance(DigiDoc4JException.class));
    assertThat(result.get(0).getMessage(), equalTo("VALUE1"));
    assertThat(result.get(0).getSignatureId(), equalTo("ID1"));
    assertThat(result.get(1).getClass(), sameInstance(DigiDoc4JException.class));
    assertThat(result.get(1).getMessage(), equalTo("VALUE2"));
    assertThat(result.get(1).getSignatureId(), equalTo("ID2"));
  }

  @Test
  public void collectWarningsAsExceptions_WhenInputContainsMessagesInSeparateLists_ReturnsListOfCorrespondingExceptions() {
    List<DigiDoc4JException> result = ReportedMessagesExtractor.collectWarningsAsExceptions(
            Collections.singletonList(new ReportedMessagesExtractor.Message("KEY1", "VALUE1", "ID1")),
            Collections.singletonList(new ReportedMessagesExtractor.Message("KEY2", "VALUE2", "ID2"))
    );

    assertThat(result, hasSize(2));
    assertThat(result.get(0).getClass(), sameInstance(DigiDoc4JException.class));
    assertThat(result.get(0).getMessage(), equalTo("VALUE1"));
    assertThat(result.get(0).getSignatureId(), equalTo("ID1"));
    assertThat(result.get(1).getClass(), sameInstance(DigiDoc4JException.class));
    assertThat(result.get(1).getMessage(), equalTo("VALUE2"));
    assertThat(result.get(1).getSignatureId(), equalTo("ID2"));
  }

  private static XmlDetails createXmlDetailsWithErrors(XmlMessage... messages) {
    XmlDetails xmlDetails = new XmlDetails();
    xmlDetails.getError().addAll(Arrays.asList(messages));
    return xmlDetails;
  }

  private static XmlDetails createXmlDetailsWithWarnings(XmlMessage... messages) {
    XmlDetails xmlDetails = new XmlDetails();
    xmlDetails.getWarning().addAll(Arrays.asList(messages));
    return xmlDetails;
  }

  private static XmlMessage createXmlMessage(String key, String value) {
    XmlMessage xmlMessage = new XmlMessage();
    xmlMessage.setKey(key);
    xmlMessage.setValue(value);
    return xmlMessage;
  }

}
