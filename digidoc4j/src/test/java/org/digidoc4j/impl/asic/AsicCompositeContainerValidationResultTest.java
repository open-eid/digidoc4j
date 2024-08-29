/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.simplereport.SimpleReport;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.digidoc4j.impl.asic.report.TimestampValidationReport;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@RunWith(MockitoJUnitRunner.class)
public class AsicCompositeContainerValidationResultTest {

  private static final String TOKEN_ID = "test-token-ID";

  @Mock
  private AsicContainerValidationResult nestingContainerValidationResult;
  @Mock
  private ContainerValidationResult nestedContainerValidationResult;

  private AsicCompositeContainerValidationResult compositeValidationResult;

  @Before
  public void setUpCompositeValidationResult() {
    // @InjectMocks does not work correctly with overlapping parameter types, create testable object manually
    compositeValidationResult = new AsicCompositeContainerValidationResult(
            nestingContainerValidationResult,
            nestedContainerValidationResult
    );
  }

  @Test
  public void isValid_WhenBothValidationResultsReturnFalse_ReturnsFalse() {
    doReturn(false).when(nestedContainerValidationResult).isValid();

    boolean result = compositeValidationResult.isValid();

    assertThat(result, equalTo(false));
    verify(nestedContainerValidationResult).isValid();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void isValid_WhenOnlyNestedValidationResultReturnsTrue_ReturnsFalse() {
    doReturn(false).when(nestingContainerValidationResult).isValid();
    doReturn(true).when(nestedContainerValidationResult).isValid();

    boolean result = compositeValidationResult.isValid();

    assertThat(result, equalTo(false));
    verify(nestedContainerValidationResult).isValid();
    verify(nestingContainerValidationResult).isValid();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void isValid_WhenBothValidationResultsReturnTrue_ReturnsTrue() {
    doReturn(true).when(nestingContainerValidationResult).isValid();
    doReturn(true).when(nestedContainerValidationResult).isValid();

    boolean result = compositeValidationResult.isValid();

    assertThat(result, equalTo(true));
    verify(nestedContainerValidationResult).isValid();
    verify(nestingContainerValidationResult).isValid();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void hasWarnings_WhenBothValidationResultsReturnFalse_ReturnsFalse() {
    doReturn(false).when(nestingContainerValidationResult).hasWarnings();
    doReturn(false).when(nestedContainerValidationResult).hasWarnings();

    boolean result = compositeValidationResult.hasWarnings();

    assertThat(result, equalTo(false));
    verify(nestedContainerValidationResult).hasWarnings();
    verify(nestingContainerValidationResult).hasWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void hasWarnings_WhenNestingValidationResultReturnsTrue_ReturnsTrue() {
    doReturn(true).when(nestingContainerValidationResult).hasWarnings();
    doReturn(false).when(nestedContainerValidationResult).hasWarnings();

    boolean result = compositeValidationResult.hasWarnings();

    assertThat(result, equalTo(true));
    verify(nestedContainerValidationResult).hasWarnings();
    verify(nestingContainerValidationResult).hasWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void hasWarnings_WhenNestedValidationResultReturnsTrue_ReturnsTrue() {
    doReturn(true).when(nestedContainerValidationResult).hasWarnings();

    boolean result = compositeValidationResult.hasWarnings();

    assertThat(result, equalTo(true));
    verify(nestedContainerValidationResult).hasWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getErrors_WhenBothListsAreNull_ReturnsEmptyList() {
    doReturn(null).when(nestingContainerValidationResult).getErrors();
    doReturn(null).when(nestedContainerValidationResult).getErrors();

    List<DigiDoc4JException> result = compositeValidationResult.getErrors();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getErrors();
    verify(nestingContainerValidationResult).getErrors();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getErrors_WhenBothListsAreEmpty_ReturnsEmptyList() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getErrors();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getErrors();

    List<DigiDoc4JException> result = compositeValidationResult.getErrors();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getErrors();
    verify(nestingContainerValidationResult).getErrors();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getErrors_WhenNestedValidationResultContainsException_ReturnsListContainingGivenException() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getErrors();
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Exception message");
    doReturn(Collections.singletonList(digiDoc4JException)).when(nestedContainerValidationResult).getErrors();

    List<DigiDoc4JException> result = compositeValidationResult.getErrors();

    assertThat(result, equalTo(Collections.singletonList(digiDoc4JException)));
    verify(nestedContainerValidationResult).getErrors();
    verify(nestingContainerValidationResult).getErrors();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getErrors_WhenNestingValidationResultContainsException_ReturnsListContainingGivenException() {
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Exception message");
    doReturn(Collections.singletonList(digiDoc4JException)).when(nestingContainerValidationResult).getErrors();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getErrors();

    List<DigiDoc4JException> result = compositeValidationResult.getErrors();

    assertThat(result, equalTo(Collections.singletonList(digiDoc4JException)));
    verify(nestedContainerValidationResult).getErrors();
    verify(nestingContainerValidationResult).getErrors();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getErrors_WhenBothListsContainExceptions_ReturnsAggregatedListOfGivenExceptions() {
    DigiDoc4JException digiDoc4JException1 = new DigiDoc4JException("Exception message 1");
    doReturn(Collections.singletonList(digiDoc4JException1)).when(nestingContainerValidationResult).getErrors();
    DigiDoc4JException digiDoc4JException2 = new DigiDoc4JException("Exception message 2");
    doReturn(Collections.singletonList(digiDoc4JException2)).when(nestedContainerValidationResult).getErrors();

    List<DigiDoc4JException> result = compositeValidationResult.getErrors();

    assertThat(result, equalTo(Arrays.asList(digiDoc4JException2, digiDoc4JException1)));
    verify(nestedContainerValidationResult).getErrors();
    verify(nestingContainerValidationResult).getErrors();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getWarnings_WhenBothListsAreNull_ReturnsEmptyList() {
    doReturn(null).when(nestingContainerValidationResult).getWarnings();
    doReturn(null).when(nestedContainerValidationResult).getWarnings();

    List<DigiDoc4JException> result = compositeValidationResult.getWarnings();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getWarnings();
    verify(nestingContainerValidationResult).getWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getWarnings_WhenBothListsAreEmpty_ReturnsEmptyList() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getWarnings();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getWarnings();

    List<DigiDoc4JException> result = compositeValidationResult.getWarnings();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getWarnings();
    verify(nestingContainerValidationResult).getWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getWarnings_WhenNestedValidationResultContainsException_ReturnsListContainingGivenException() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getWarnings();
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Exception message");
    doReturn(Collections.singletonList(digiDoc4JException)).when(nestedContainerValidationResult).getWarnings();

    List<DigiDoc4JException> result = compositeValidationResult.getWarnings();

    assertThat(result, equalTo(Collections.singletonList(digiDoc4JException)));
    verify(nestedContainerValidationResult).getWarnings();
    verify(nestingContainerValidationResult).getWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getWarnings_WhenNestingValidationResultContainsException_ReturnsListContainingGivenException() {
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Exception message");
    doReturn(Collections.singletonList(digiDoc4JException)).when(nestingContainerValidationResult).getWarnings();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getWarnings();

    List<DigiDoc4JException> result = compositeValidationResult.getWarnings();

    assertThat(result, equalTo(Collections.singletonList(digiDoc4JException)));
    verify(nestedContainerValidationResult).getWarnings();
    verify(nestingContainerValidationResult).getWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getWarnings_WhenBothListsContainExceptions_ReturnsAggregatedListOfGivenExceptions() {
    DigiDoc4JException digiDoc4JException1 = new DigiDoc4JException("Exception message 1");
    doReturn(Collections.singletonList(digiDoc4JException1)).when(nestingContainerValidationResult).getWarnings();
    DigiDoc4JException digiDoc4JException2 = new DigiDoc4JException("Exception message 2");
    doReturn(Collections.singletonList(digiDoc4JException2)).when(nestedContainerValidationResult).getWarnings();

    List<DigiDoc4JException> result = compositeValidationResult.getWarnings();

    assertThat(result, equalTo(Arrays.asList(digiDoc4JException2, digiDoc4JException1)));
    verify(nestedContainerValidationResult).getWarnings();
    verify(nestingContainerValidationResult).getWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getContainerErrors_WhenBothListsAreNull_ReturnsEmptyList() {
    doReturn(null).when(nestingContainerValidationResult).getContainerErrors();
    doReturn(null).when(nestedContainerValidationResult).getContainerErrors();

    List<DigiDoc4JException> result = compositeValidationResult.getContainerErrors();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getContainerErrors();
    verify(nestingContainerValidationResult).getContainerErrors();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getContainerErrors_WhenBothListsAreEmpty_ReturnsEmptyList() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getContainerErrors();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getContainerErrors();

    List<DigiDoc4JException> result = compositeValidationResult.getContainerErrors();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getContainerErrors();
    verify(nestingContainerValidationResult).getContainerErrors();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getContainerErrors_WhenNestedValidationResultContainsException_ReturnsListContainingGivenException() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getContainerErrors();
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Exception message");
    doReturn(Collections.singletonList(digiDoc4JException)).when(nestedContainerValidationResult).getContainerErrors();

    List<DigiDoc4JException> result = compositeValidationResult.getContainerErrors();

    assertThat(result, equalTo(Collections.singletonList(digiDoc4JException)));
    verify(nestedContainerValidationResult).getContainerErrors();
    verify(nestingContainerValidationResult).getContainerErrors();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getContainerErrors_WhenNestingValidationResultContainsException_ReturnsListContainingGivenException() {
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Exception message");
    doReturn(Collections.singletonList(digiDoc4JException)).when(nestingContainerValidationResult).getContainerErrors();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getContainerErrors();

    List<DigiDoc4JException> result = compositeValidationResult.getContainerErrors();

    assertThat(result, equalTo(Collections.singletonList(digiDoc4JException)));
    verify(nestedContainerValidationResult).getContainerErrors();
    verify(nestingContainerValidationResult).getContainerErrors();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getContainerErrors_WhenBothListsContainExceptions_ReturnsAggregatedListOfGivenExceptions() {
    DigiDoc4JException digiDoc4JException1 = new DigiDoc4JException("Exception message 1");
    doReturn(Collections.singletonList(digiDoc4JException1)).when(nestingContainerValidationResult).getContainerErrors();
    DigiDoc4JException digiDoc4JException2 = new DigiDoc4JException("Exception message 2");
    doReturn(Collections.singletonList(digiDoc4JException2)).when(nestedContainerValidationResult).getContainerErrors();

    List<DigiDoc4JException> result = compositeValidationResult.getContainerErrors();

    assertThat(result, equalTo(Arrays.asList(digiDoc4JException2, digiDoc4JException1)));
    verify(nestedContainerValidationResult).getContainerErrors();
    verify(nestingContainerValidationResult).getContainerErrors();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getContainerWarnings_WhenBothListsAreNull_ReturnsEmptyList() {
    doReturn(null).when(nestingContainerValidationResult).getContainerWarnings();
    doReturn(null).when(nestedContainerValidationResult).getContainerWarnings();

    List<DigiDoc4JException> result = compositeValidationResult.getContainerWarnings();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getContainerWarnings();
    verify(nestingContainerValidationResult).getContainerWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getContainerWarnings_WhenBothListsAreEmpty_ReturnsEmptyList() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getContainerWarnings();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getContainerWarnings();

    List<DigiDoc4JException> result = compositeValidationResult.getContainerWarnings();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getContainerWarnings();
    verify(nestingContainerValidationResult).getContainerWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getContainerWarnings_WhenNestedValidationResultContainsException_ReturnsListContainingGivenException() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getContainerWarnings();
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Exception message");
    doReturn(Collections.singletonList(digiDoc4JException)).when(nestedContainerValidationResult).getContainerWarnings();

    List<DigiDoc4JException> result = compositeValidationResult.getContainerWarnings();

    assertThat(result, equalTo(Collections.singletonList(digiDoc4JException)));
    verify(nestedContainerValidationResult).getContainerWarnings();
    verify(nestingContainerValidationResult).getContainerWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getContainerWarnings_WhenNestingValidationResultContainsException_ReturnsListContainingGivenException() {
    DigiDoc4JException digiDoc4JException = new DigiDoc4JException("Exception message");
    doReturn(Collections.singletonList(digiDoc4JException)).when(nestingContainerValidationResult).getContainerWarnings();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getContainerWarnings();

    List<DigiDoc4JException> result = compositeValidationResult.getContainerWarnings();

    assertThat(result, equalTo(Collections.singletonList(digiDoc4JException)));
    verify(nestedContainerValidationResult).getContainerWarnings();
    verify(nestingContainerValidationResult).getContainerWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getContainerWarnings_WhenBothListsContainExceptions_ReturnsAggregatedListOfGivenExceptions() {
    DigiDoc4JException digiDoc4JException1 = new DigiDoc4JException("Exception message 1");
    doReturn(Collections.singletonList(digiDoc4JException1)).when(nestingContainerValidationResult).getContainerWarnings();
    DigiDoc4JException digiDoc4JException2 = new DigiDoc4JException("Exception message 2");
    doReturn(Collections.singletonList(digiDoc4JException2)).when(nestedContainerValidationResult).getContainerWarnings();

    List<DigiDoc4JException> result = compositeValidationResult.getContainerWarnings();

    assertThat(result, equalTo(Arrays.asList(digiDoc4JException2, digiDoc4JException1)));
    verify(nestedContainerValidationResult).getContainerWarnings();
    verify(nestingContainerValidationResult).getContainerWarnings();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSimpleReports_WhenBothListsAreNull_ReturnsEmptyList() {
    doReturn(null).when(nestingContainerValidationResult).getSimpleReports();
    doReturn(null).when(nestedContainerValidationResult).getSimpleReports();

    List<SimpleReport> result = compositeValidationResult.getSimpleReports();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getSimpleReports();
    verify(nestingContainerValidationResult).getSimpleReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSimpleReports_WhenBothListsAreEmpty_ReturnsEmptyList() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getSimpleReports();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getSimpleReports();

    List<SimpleReport> result = compositeValidationResult.getSimpleReports();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getSimpleReports();
    verify(nestingContainerValidationResult).getSimpleReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSimpleReports_WhenNestedValidationResultContainsException_ReturnsListContainingGivenException() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getSimpleReports();
    SimpleReport simpleReport = mock(SimpleReport.class);
    doReturn(Collections.singletonList(simpleReport)).when(nestedContainerValidationResult).getSimpleReports();

    List<SimpleReport> result = compositeValidationResult.getSimpleReports();

    assertThat(result, equalTo(Collections.singletonList(simpleReport)));
    verify(nestedContainerValidationResult).getSimpleReports();
    verify(nestingContainerValidationResult).getSimpleReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSimpleReports_WhenNestingValidationResultContainsException_ReturnsListContainingGivenException() {
    SimpleReport simpleReport = mock(SimpleReport.class);
    doReturn(Collections.singletonList(simpleReport)).when(nestingContainerValidationResult).getSimpleReports();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getSimpleReports();

    List<SimpleReport> result = compositeValidationResult.getSimpleReports();

    assertThat(result, equalTo(Collections.singletonList(simpleReport)));
    verify(nestedContainerValidationResult).getSimpleReports();
    verify(nestingContainerValidationResult).getSimpleReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSimpleReports_WhenBothListsContainExceptions_ReturnsAggregatedListOfGivenExceptions() {
    SimpleReport simpleReport1 = mock(SimpleReport.class);
    doReturn(Collections.singletonList(simpleReport1)).when(nestingContainerValidationResult).getSimpleReports();
    SimpleReport simpleReport2 = mock(SimpleReport.class);
    doReturn(Collections.singletonList(simpleReport2)).when(nestedContainerValidationResult).getSimpleReports();

    List<SimpleReport> result = compositeValidationResult.getSimpleReports();

    assertThat(result, equalTo(Arrays.asList(simpleReport2, simpleReport1)));
    verify(nestedContainerValidationResult).getSimpleReports();
    verify(nestingContainerValidationResult).getSimpleReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSignatureReports_WhenBothListsAreNull_ReturnsEmptyList() {
    doReturn(null).when(nestingContainerValidationResult).getSignatureReports();
    doReturn(null).when(nestedContainerValidationResult).getSignatureReports();

    List<SignatureValidationReport> result = compositeValidationResult.getSignatureReports();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getSignatureReports();
    verify(nestingContainerValidationResult).getSignatureReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSignatureReports_WhenBothListsAreEmpty_ReturnsEmptyList() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getSignatureReports();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getSignatureReports();

    List<SignatureValidationReport> result = compositeValidationResult.getSignatureReports();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getSignatureReports();
    verify(nestingContainerValidationResult).getSignatureReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSignatureReports_WhenNestedValidationResultContainsException_ReturnsListContainingGivenException() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getSignatureReports();
    SignatureValidationReport signatureValidationReport = mock(SignatureValidationReport.class);
    doReturn(Collections.singletonList(signatureValidationReport)).when(nestedContainerValidationResult).getSignatureReports();

    List<SignatureValidationReport> result = compositeValidationResult.getSignatureReports();

    assertThat(result, equalTo(Collections.singletonList(signatureValidationReport)));
    verify(nestedContainerValidationResult).getSignatureReports();
    verify(nestingContainerValidationResult).getSignatureReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSignatureReports_WhenNestingValidationResultContainsException_ReturnsListContainingGivenException() {
    SignatureValidationReport signatureValidationReport = mock(SignatureValidationReport.class);
    doReturn(Collections.singletonList(signatureValidationReport)).when(nestingContainerValidationResult).getSignatureReports();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getSignatureReports();

    List<SignatureValidationReport> result = compositeValidationResult.getSignatureReports();

    assertThat(result, equalTo(Collections.singletonList(signatureValidationReport)));
    verify(nestedContainerValidationResult).getSignatureReports();
    verify(nestingContainerValidationResult).getSignatureReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSignatureReports_WhenBothListsContainExceptions_ReturnsAggregatedListOfGivenExceptions() {
    SignatureValidationReport signatureValidationReport1 = mock(SignatureValidationReport.class);
    doReturn(Collections.singletonList(signatureValidationReport1)).when(nestingContainerValidationResult).getSignatureReports();
    SignatureValidationReport signatureValidationReport2 = mock(SignatureValidationReport.class);
    doReturn(Collections.singletonList(signatureValidationReport2)).when(nestedContainerValidationResult).getSignatureReports();

    List<SignatureValidationReport> result = compositeValidationResult.getSignatureReports();

    assertThat(result, equalTo(Arrays.asList(signatureValidationReport2, signatureValidationReport1)));
    verify(nestedContainerValidationResult).getSignatureReports();
    verify(nestingContainerValidationResult).getSignatureReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getTimestampReports_WhenBothListsAreNull_ReturnsEmptyList() {
    doReturn(null).when(nestingContainerValidationResult).getTimestampReports();
    doReturn(null).when(nestedContainerValidationResult).getTimestampReports();

    List<TimestampValidationReport> result = compositeValidationResult.getTimestampReports();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getTimestampReports();
    verify(nestingContainerValidationResult).getTimestampReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getTimestampReports_WhenBothListsAreEmpty_ReturnsEmptyList() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getTimestampReports();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getTimestampReports();

    List<TimestampValidationReport> result = compositeValidationResult.getTimestampReports();

    assertThat(result, empty());
    verify(nestedContainerValidationResult).getTimestampReports();
    verify(nestingContainerValidationResult).getTimestampReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getTimestampReports_WhenNestedValidationResultContainsException_ReturnsListContainingGivenException() {
    doReturn(Collections.emptyList()).when(nestingContainerValidationResult).getTimestampReports();
    TimestampValidationReport timestampValidationReport = mock(TimestampValidationReport.class);
    doReturn(Collections.singletonList(timestampValidationReport)).when(nestedContainerValidationResult).getTimestampReports();

    List<TimestampValidationReport> result = compositeValidationResult.getTimestampReports();

    assertThat(result, equalTo(Collections.singletonList(timestampValidationReport)));
    verify(nestedContainerValidationResult).getTimestampReports();
    verify(nestingContainerValidationResult).getTimestampReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getTimestampReports_WhenNestingValidationResultContainsException_ReturnsListContainingGivenException() {
    TimestampValidationReport timestampValidationReport = mock(TimestampValidationReport.class);
    doReturn(Collections.singletonList(timestampValidationReport)).when(nestingContainerValidationResult).getTimestampReports();
    doReturn(Collections.emptyList()).when(nestedContainerValidationResult).getTimestampReports();

    List<TimestampValidationReport> result = compositeValidationResult.getTimestampReports();

    assertThat(result, equalTo(Collections.singletonList(timestampValidationReport)));
    verify(nestedContainerValidationResult).getTimestampReports();
    verify(nestingContainerValidationResult).getTimestampReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getTimestampReports_WhenBothListsContainExceptions_ReturnsAggregatedListOfGivenExceptions() {
    TimestampValidationReport timestampValidationReport1 = mock(TimestampValidationReport.class);
    doReturn(Collections.singletonList(timestampValidationReport1)).when(nestingContainerValidationResult).getTimestampReports();
    TimestampValidationReport timestampValidationReport2 = mock(TimestampValidationReport.class);
    doReturn(Collections.singletonList(timestampValidationReport2)).when(nestedContainerValidationResult).getTimestampReports();

    List<TimestampValidationReport> result = compositeValidationResult.getTimestampReports();

    assertThat(result, equalTo(Arrays.asList(timestampValidationReport2, timestampValidationReport1)));
    verify(nestedContainerValidationResult).getTimestampReports();
    verify(nestingContainerValidationResult).getTimestampReports();
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getIndication_WhenBothValidationResultsReturnNull_ReturnsNull() {
    doReturn(null).when(nestingContainerValidationResult).getIndication(TOKEN_ID);
    doReturn(null).when(nestedContainerValidationResult).getIndication(TOKEN_ID);

    Indication result = compositeValidationResult.getIndication(TOKEN_ID);

    assertThat(result, nullValue());
    verify(nestedContainerValidationResult).getIndication(TOKEN_ID);
    verify(nestingContainerValidationResult).getIndication(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getIndication_WhenNestingValidationResultReturnsIndication_ReturnsGivenIndication() {
    doReturn(Indication.INDETERMINATE).when(nestingContainerValidationResult).getIndication(TOKEN_ID);
    doReturn(null).when(nestedContainerValidationResult).getIndication(TOKEN_ID);

    Indication result = compositeValidationResult.getIndication(TOKEN_ID);

    assertThat(result, sameInstance(Indication.INDETERMINATE));
    verify(nestedContainerValidationResult).getIndication(TOKEN_ID);
    verify(nestingContainerValidationResult).getIndication(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getIndication_WhenNestedValidationResultReturnsIndication_ReturnsGivenIndication() {
    doReturn(Indication.NO_SIGNATURE_FOUND).when(nestedContainerValidationResult).getIndication(TOKEN_ID);

    Indication result = compositeValidationResult.getIndication(TOKEN_ID);

    assertThat(result, sameInstance(Indication.NO_SIGNATURE_FOUND));
    verify(nestedContainerValidationResult).getIndication(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSubIndication_WhenBothValidationResultsReturnNull_ReturnsNull() {
    doReturn(null).when(nestingContainerValidationResult).getSubIndication(TOKEN_ID);
    doReturn(null).when(nestedContainerValidationResult).getSubIndication(TOKEN_ID);

    SubIndication result = compositeValidationResult.getSubIndication(TOKEN_ID);

    assertThat(result, nullValue());
    verify(nestedContainerValidationResult).getSubIndication(TOKEN_ID);
    verify(nestingContainerValidationResult).getSubIndication(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSubIndication_WhenNestingValidationResultReturnsSubIndication_ReturnsGivenSubIndication() {
    doReturn(SubIndication.HASH_FAILURE).when(nestingContainerValidationResult).getSubIndication(TOKEN_ID);
    doReturn(null).when(nestedContainerValidationResult).getSubIndication(TOKEN_ID);

    SubIndication result = compositeValidationResult.getSubIndication(TOKEN_ID);

    assertThat(result, sameInstance(SubIndication.HASH_FAILURE));
    verify(nestedContainerValidationResult).getSubIndication(TOKEN_ID);
    verify(nestingContainerValidationResult).getSubIndication(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSubIndication_WhenNestedValidationResultReturnsSubIndication_ReturnsGivenSubIndication() {
    doReturn(SubIndication.NOT_YET_VALID).when(nestedContainerValidationResult).getSubIndication(TOKEN_ID);

    SubIndication result = compositeValidationResult.getSubIndication(TOKEN_ID);

    assertThat(result, sameInstance(SubIndication.NOT_YET_VALID));
    verify(nestedContainerValidationResult).getSubIndication(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSignatureQualification_WhenBothValidationResultsReturnNull_ReturnsNull() {
    doReturn(null).when(nestingContainerValidationResult).getSignatureQualification(TOKEN_ID);
    doReturn(null).when(nestedContainerValidationResult).getSignatureQualification(TOKEN_ID);

    SignatureQualification result = compositeValidationResult.getSignatureQualification(TOKEN_ID);

    assertThat(result, nullValue());
    verify(nestedContainerValidationResult).getSignatureQualification(TOKEN_ID);
    verify(nestingContainerValidationResult).getSignatureQualification(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSignatureQualification_WhenNestingValidationResultReturnsQualification_ReturnsGivenQualification() {
    doReturn(SignatureQualification.ADESIG).when(nestingContainerValidationResult).getSignatureQualification(TOKEN_ID);
    doReturn(null).when(nestedContainerValidationResult).getSignatureQualification(TOKEN_ID);

    SignatureQualification result = compositeValidationResult.getSignatureQualification(TOKEN_ID);

    assertThat(result, sameInstance(SignatureQualification.ADESIG));
    verify(nestedContainerValidationResult).getSignatureQualification(TOKEN_ID);
    verify(nestingContainerValidationResult).getSignatureQualification(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getSignatureQualification_WhenNestedValidationResultReturnsQualification_ReturnsGivenQualification() {
    doReturn(SignatureQualification.ADESEAL).when(nestedContainerValidationResult).getSignatureQualification(TOKEN_ID);

    SignatureQualification result = compositeValidationResult.getSignatureQualification(TOKEN_ID);

    assertThat(result, sameInstance(SignatureQualification.ADESEAL));
    verify(nestedContainerValidationResult).getSignatureQualification(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getTimestampQualification_WhenBothValidationResultsReturnNull_ReturnsNull() {
    doReturn(null).when(nestingContainerValidationResult).getTimestampQualification(TOKEN_ID);
    doReturn(null).when(nestedContainerValidationResult).getTimestampQualification(TOKEN_ID);

    TimestampQualification result = compositeValidationResult.getTimestampQualification(TOKEN_ID);

    assertThat(result, nullValue());
    verify(nestedContainerValidationResult).getTimestampQualification(TOKEN_ID);
    verify(nestingContainerValidationResult).getTimestampQualification(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getTimestampQualification_WhenNestingValidationResultReturnsQualification_ReturnsGivenQualification() {
    doReturn(TimestampQualification.TSA).when(nestingContainerValidationResult).getTimestampQualification(TOKEN_ID);
    doReturn(null).when(nestedContainerValidationResult).getTimestampQualification(TOKEN_ID);

    TimestampQualification result = compositeValidationResult.getTimestampQualification(TOKEN_ID);

    assertThat(result, sameInstance(TimestampQualification.TSA));
    verify(nestedContainerValidationResult).getTimestampQualification(TOKEN_ID);
    verify(nestingContainerValidationResult).getTimestampQualification(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void getTimestampQualification_WhenNestedValidationResultReturnsQualification_ReturnsGivenQualification() {
    doReturn(TimestampQualification.QTSA).when(nestedContainerValidationResult).getTimestampQualification(TOKEN_ID);

    TimestampQualification result = compositeValidationResult.getTimestampQualification(TOKEN_ID);

    assertThat(result, sameInstance(TimestampQualification.QTSA));
    verify(nestedContainerValidationResult).getTimestampQualification(TOKEN_ID);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

  @Test
  public void saveXmlReports_WhenValidPathIsGiven_RequestIsDelegatedToBothValidationResults() {
    Path path = mock(Path.class);

    compositeValidationResult.saveXmlReports(path);

    verify(nestedContainerValidationResult).saveXmlReports(path);
    verify(nestingContainerValidationResult).saveXmlReports(path);
    verifyNoMoreInteractions(nestingContainerValidationResult, nestedContainerValidationResult);
  }

}
