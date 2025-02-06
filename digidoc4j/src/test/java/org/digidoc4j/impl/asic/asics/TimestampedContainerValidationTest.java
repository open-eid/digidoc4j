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
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.impl.asic.report.TimestampValidationReport;
import org.digidoc4j.test.TestConstants;
import org.junit.Test;

import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValidIgnoreErrors;
import static org.digidoc4j.test.TestAssert.assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages;
import static org.digidoc4j.test.TestAssert.assertContainsExactSetOfErrors;
import static org.digidoc4j.test.matcher.CommonMatchers.equalToIsoDate;
import static org.digidoc4j.test.matcher.CommonMatchers.equalToTimestampUniqueIdList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

public class TimestampedContainerValidationTest extends AbstractTest {

  @Test
  public void validate_WhenAsicsWithOneValidTimestamp_ValidationResultContainsInfoAboutOneValidTimestamp() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/testtimestamp.asics",
            Configuration.of(Configuration.Mode.TEST)
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValid(containerValidationResult);
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getContainerErrors(), empty());
    assertThat(containerValidationResult.getContainerWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), empty());
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(1));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2014_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2017-11-24T08:20:33Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
  }

  @Test
  public void validate_WhenAsicsWith3ValidTimestamps_ValidationResultContainsInfoAbout3ValidTimestamps() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/3xTST-text-data-file.asics",
            Configuration.of(Configuration.Mode.TEST)
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValid(containerValidationResult);
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getContainerErrors(), empty());
    assertThat(containerValidationResult.getContainerWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(3));
    assertThat(containerValidationResult.getSignatureIdList(), empty());
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(3));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-07-05T08:42:57Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(1).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(1);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-07-05T08:44:04Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(2).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(2);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-07-05T08:45:10Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
  }

  @Test
  public void validate_WhenAsicsWith1ValidAnd2InvalidTimestamps_ValidationResultContainsErrors() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/invalid-containers/3xTST-text-data-file-hash-failure-since-2nd-tst.asics",
            Configuration.of(Configuration.Mode.TEST)
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValidIgnoreErrors(containerValidationResult);
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getErrors(), 2,
            container.getTimestamps().get(1).getUniqueId() + ") - The reference data object is not intact!",
            container.getTimestamps().get(2).getUniqueId() + ") - The reference data object is not intact!"
    );
    assertThat(containerValidationResult.getWarnings(), empty());
    assertThat(containerValidationResult.getContainerErrors(), empty());
    assertThat(containerValidationResult.getContainerWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(3));
    assertThat(containerValidationResult.getSignatureIdList(), empty());
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(3));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-05-20T07:58:12Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(1).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(containerValidationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(1);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-05-20T07:59:20Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              timestampValidationResult.getErrors(), 1,
              timestampId + ") - The reference data object is not intact!"
      );
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(2).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(containerValidationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(2);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.DEMO_SK_TSA_2023E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-05-20T08:00:25Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              timestampValidationResult.getErrors(), 1,
              timestampId + ") - The reference data object is not intact!"
      );
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
  }

  @Test
  public void validate_WhenAsicsWithOneExpiredTimestamp_ValidationResultIsValidAndContainsWarnings() {
    Container container = ContainerOpener.open(
            "src/test/resources/prodFiles/invalid-containers/1xTST-text-data-file-expired-tst.asics",
            Configuration.of(Configuration.Mode.PROD)
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValid(containerValidationResult);
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getWarnings(), 1,
            container.getTimestamps().get(0).getUniqueId() + ") - The certificate is not related to a granted status at time-stamp lowest POE time!"
    );
    assertThat(containerValidationResult.getContainerErrors(), empty());
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getContainerWarnings(), 1,
            "Found a timestamp token not related to granted status. " +
                    "If not yet covered with a fresh timestamp token, this container might become invalid in the future."
    );
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureIdList(), empty());
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(1));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.TSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.SK_TSA_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2017-08-25T09:56:33Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              timestampValidationResult.getWarnings(), 1,
              timestampId + ") - The certificate is not related to a granted status at time-stamp lowest POE time!"
      );
    }
  }

  @Test
  public void validate_WhenAsicsWithOneExpiredAndOneValidTimestamp_ValidationResultIsValidAndContainsWarnings() {
    Container container = ContainerOpener.open(
            "src/test/resources/prodFiles/valid-containers/2xTST-text-data-file-expired-tst-and-valid-tst.asics",
            Configuration.of(Configuration.Mode.PROD)
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValid(containerValidationResult);
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getWarnings(), 1,
            container.getTimestamps().get(0).getUniqueId() + ") - The certificate is not related to a granted status at time-stamp lowest POE time!"
    );
    assertThat(containerValidationResult.getContainerErrors(), empty());
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getContainerWarnings(), 1,
            "Found a timestamp token not related to granted status. " +
                    "If not yet covered with a fresh timestamp token, this container might become invalid in the future."
    );
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(2));
    assertThat(containerValidationResult.getSignatureIdList(), empty());
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(2));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.TSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.SK_TSA_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2017-08-25T09:56:33Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              timestampValidationResult.getWarnings(), 1,
              timestampId + ") - The certificate is not related to a granted status at time-stamp lowest POE time!"
      );
    }
    {
      String timestampId = container.getTimestamps().get(1).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(1);
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.SK_TSA_2024E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-10-25T09:28:21Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
  }

  @Test
  public void validate_WhenAsicsWithInvalidAndNonCoveringTimestamp_ValidationResultIsValidButContainsErrorsAndWarnings() {
    Container container = ContainerOpener.open(
            "src/test/resources/prodFiles/invalid-containers/2xTST-text-data-file-1st-tst-invalid-2nd-tst-no-coverage.asics",
            Configuration.of(Configuration.Mode.PROD)
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValidIgnoreErrors(containerValidationResult);
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getErrors(), 1,
            container.getTimestamps().get(0).getUniqueId() + ") - The time-stamp message imprint is not intact!"
    );
    assertContainsExactSetOfErrors(containerValidationResult.getWarnings(),
            container.getTimestamps().get(1).getUniqueId() + ") - The time-stamp token does not cover container datafile!");
    assertThat(containerValidationResult.getContainerErrors(), empty());
    assertThat(containerValidationResult.getContainerWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(2));
    assertThat(containerValidationResult.getSignatureIdList(), empty());
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(2));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(containerValidationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getWarnings(), empty());
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.SK_TSA_2024E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-09-13T10:49:58Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              timestampValidationResult.getErrors(), 1,
              timestampId + ") - The time-stamp message imprint is not intact!"
      );
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(1).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(1);
      assertThat(timestampReport.getWarnings(), contains("The time-stamp token does not cover container datafile!"));
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.SK_TSA_2024E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-09-13T11:20:02Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertContainsExactSetOfErrors(timestampValidationResult.getWarnings(),
              timestampId + ") - The time-stamp token does not cover container datafile!"
      );
    }
  }

  @Test
  public void validate_WhenAsicsWithInvalidAndNonCoveringAndValidTimestamp_ValidationResultIsValidButContainsErrorsAndWarnings() {
    Container container = ContainerOpener.open(
            "src/test/resources/prodFiles/valid-containers/3xTST-text-data-file-1st-tst-invalid-2nd-tst-no-coverage-3rd-tst-valid.asics",
            Configuration.of(Configuration.Mode.PROD)
    );

    ContainerValidationResult containerValidationResult = container.validate();

    assertContainerIsValidIgnoreErrors(containerValidationResult);
    assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
            containerValidationResult.getErrors(), 1,
            container.getTimestamps().get(0).getUniqueId() + ") - The time-stamp message imprint is not intact!"
    );
    assertContainsExactSetOfErrors(containerValidationResult.getWarnings(),
            container.getTimestamps().get(1).getUniqueId() + ") - The time-stamp token does not cover container datafile!");
    assertThat(containerValidationResult.getContainerErrors(), empty());
    assertThat(containerValidationResult.getContainerWarnings(), empty());
    assertThat(containerValidationResult.getSimpleReports(), hasSize(1));
    assertThat(containerValidationResult.getSignatureReports(), empty());
    assertThat(containerValidationResult.getTimestampReports(), hasSize(3));
    assertThat(containerValidationResult.getSignatureIdList(), empty());
    assertThat(containerValidationResult.getTimestampIdList(), hasSize(3));
    assertThat(containerValidationResult.getTimestampIdList(), equalToTimestampUniqueIdList(container));
    {
      String timestampId = container.getTimestamps().get(0).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.FAILED));
      assertThat(containerValidationResult.getSubIndication(timestampId), sameInstance(SubIndication.HASH_FAILURE));
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(0);
      assertThat(timestampReport.getWarnings(), empty());
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.SK_TSA_2024E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-09-13T10:49:58Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(false));
      assertContainsExactNumberOfErrorsAndAllExpectedErrorMessages(
              timestampValidationResult.getErrors(), 1,
              timestampId + ") - The time-stamp message imprint is not intact!"
      );
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
    {
      String timestampId = container.getTimestamps().get(1).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(1);
      assertThat(timestampReport.getWarnings(), contains("The time-stamp token does not cover container datafile!"));
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.SK_TSA_2024E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-09-13T11:20:02Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertContainsExactSetOfErrors(timestampValidationResult.getWarnings(),
              timestampId + ") - The time-stamp token does not cover container datafile!"
      );
    }
    {
      String timestampId = container.getTimestamps().get(2).getUniqueId();
      assertThat(containerValidationResult.getIndication(timestampId), sameInstance(Indication.PASSED));
      assertThat(containerValidationResult.getSubIndication(timestampId), nullValue());
      assertThat(containerValidationResult.getTimestampQualification(timestampId), sameInstance(TimestampQualification.QTSA));
      TimestampValidationReport timestampReport = containerValidationResult.getTimestampReports().get(2);
      assertThat(timestampReport.getWarnings(), empty());
      assertThat(timestampReport.getProducedBy(), equalTo(TestConstants.SK_TSA_2024E_CN));
      assertThat(timestampReport.getProductionTime(), equalToIsoDate("2024-10-25T13:25:59Z"));
      assertThat(timestampReport.getUniqueId(), equalTo(timestampId));
      ValidationResult timestampValidationResult = containerValidationResult.getValidationResult(timestampId);
      assertThat(timestampValidationResult, notNullValue());
      assertThat(timestampValidationResult.isValid(), equalTo(true));
      assertThat(timestampValidationResult.getErrors(), empty());
      assertThat(timestampValidationResult.getWarnings(), empty());
    }
  }

}
